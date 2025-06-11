require("dotenv").config();

if (
  !process.env.CLOUDINARY_CLOUD_NAME ||
  !process.env.CLOUDINARY_API_KEY ||
  !process.env.CLOUDINARY_API_SECRET ||
  !process.env.MONGO_URI ||
  !process.env.JWT_SECRET
) {
  console.error("❌ Missing required environment variables. Please check your .env file.");
  process.exit(1);
}

const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const multer = require("multer");
const cloudinary = require("cloudinary").v2;
const { CloudinaryStorage } = require("multer-storage-cloudinary");
const helmet = require("helmet");

// App Initialization
const app = express();
app.use(cors({
  origin: ['http://localhost:3000', 'https://harithi-fashion-picks.web.app'],
  credentials: true
}));
app.use(express.json());
app.use(helmet());

// Cloudinary Config
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Multer Storage for Cloudinary
const storage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: "products",
    allowed_formats: ["jpg", "jpeg", "png"],
  },
});
const upload = multer({ storage });

// MongoDB Connection
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
  })
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err);
    process.exit(1);
  });

// Mongoose Schemas
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  password: String, // hashed
  role: String, // "admin" or "customer"
});
const User = mongoose.model("User", userSchema);
const productSchema = new mongoose.Schema({
  title: { type: String, required: true },
  desc: { type: String, required: true },
  price: { type: Number, required: true }, // ✅ Required
  offerPrice: { type: Number },                 // ✅ Optional
  image: { type: String, required: true },         // ✅ Required
  image2: { type: String },
  image3: { type: String },
  image4: { type: String },
  image5: { type: String },
});


const Product = mongoose.model("Product", productSchema);

// JWT middleware
const verifyJWT = (req, res, next) => {
  let token = req.headers["authorization"];
  if (!token) {
    return res.status(403).json({ message: "No token provided" });
  }

  if (token.startsWith("Bearer ")) {
    token = token.slice(7);
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = decoded;
    next();
  });
};

// REGISTER Route (optional, for creating users)
app.post("/api/register", async (req, res) => {
  const { email, password, role } = req.body;
  try {
    const hashed = await bcrypt.hash(password, 10);
    const newUser = new User({ email, password: hashed, role });
    await newUser.save();
    res.status(201).json({ message: "User registered" });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ message: "Registration failed" });
  }
});

// LOGIN Route
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: "Invalid credentials" });

    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    res.json({ token, role: user.role });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Get All Products
app.get("/api/products", async (req, res) => {
  try {
    const products = await Product.find();
    res.json(products);
  } catch (error) {
    console.error("❌ Get products error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Upload single image
app.post("/api/upload", verifyJWT, upload.single("image"), async (req, res) => {
  try {
    if (!req.file || !req.file.path) {
      return res.status(400).json({ error: "No image uploaded" });
    }

    res.json({ imageUrl: req.file.path });
  } catch (err) {
    console.error("❌ Upload error:", err);
    res.status(500).json({ error: "Image upload failed", details: err.message });
  }
});

// Bulk Create/Update/Delete Products
app.post("/api/products/bulk", verifyJWT, async (req, res) => {
  try {
    const { create = [], update = [], delete: deleteIds = [] } = req.body;

    for (const newProduct of create) {
      await Product.create(newProduct);
    }

    for (const updProduct of update) {
      await Product.findByIdAndUpdate(updProduct._id, updProduct, { new: true });
    }

    for (const id of deleteIds) {
      await Product.findByIdAndDelete(id);
    }

    res.status(200).json({ message: "Products processed" });
  } catch (error) {
    console.error("Bulk operation error:", error);
    res.status(500).json({ error: "Failed to process bulk operations" });
  }
});

// Global error handler for unhandled promises
process.on("unhandledRejection", (reason, promise) => {
  console.error("🧨 Unhandled Rejection:", reason);
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
