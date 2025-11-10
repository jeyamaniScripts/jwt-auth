import express from "express";
import profiles from "../model/profiles.model.js";
import bcrypt from "bcryptjs";
import rateLimit from "express-rate-limit";
import jwt from "jsonwebtoken";

const router = express.Router();

const app = express();
const loginLimitter = app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000, //15 mins
    max: 50,
    message: "Too Many Request, try again later",
  })
);

function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ message: "no token provided" });
  }

  const tokenSignature = authHeader.split(" ")[1];

  jwt.verify(tokenSignature, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      if (err.name === "TokenExpiredError") {
        return res.status(401).json({ message: "access token expired" });
      } else {
        return res.status(403).json({ message: "invalid token" });
      }
    }

    req.profile = decoded;
  });
  next();
}

router.post("/api/register", async (req, res) => {
  try {
    const { name, email, role, adminCode, imageUrl, password } = req.body;
    if (!name || !email || !role || !imageUrl || !password) {
      return res.status(400).json({ message: "All Fields are required" });
    }

    let userRole = role;
    if (role === "admin" && adminCode !== process.env.adminCode) {
      return res
        .status(403)
        .json({ message: `inavalid admin code-${adminCode}` });
    } else if (role !== "admin") {
      userRole = "user";
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    await profiles.create({
      name,
      email,
      password: hashedPassword,
      role: userRole,
      imageUrl,
    });

    res.status(200).json({ message: `object created with role -${userRole}` });
  } catch (error) {
    res.status(500).json({ message: `something went wrong -${error}` });
  }
});

router.post("/api/login", loginLimitter, async (req, res) => {
  try {
    const { email, password } = req.body;

    const profile = await profiles.findOne({ email });
    if (!profile) {
      return res
        .status(404)
        .json({ message: `object with ${email} not found` });
    }

    const isMatch = await bcrypt.compare(password, profile.password);
    if (!isMatch) {
      return res.status(401).json({ message: "invalid password" });
    }

    const accessToken = jwt.sign(
      { id: profile._id, role: profile.role },
      process.env.JWT_SECRET,
      { expiresIn: "15min" }
    );

    const refreshToken = jwt.sign(
      { id: profile._id },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: "2d" }
    );

    profile.refreshToken = refreshToken;
    await profile.save();
    res
      .status(200)
      .json({ id: profile._id, accessToken, refreshToken, role: profile.role });
  } catch (error) {
    res.status(500).json({ message: `something went wrong ${error}` });
  }
});

router.get("/", verifyToken, async (req, res) => {
  try {
    if (req.profile.role === "admin") {
      const profileData = await profiles.find({}, "-password -refreshToken");
      res.status(200).json(profileData);
    } else {
      const profile = await profiles.findById(req.profile.id);
      res.status(200).json(profile);
    }
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

router.post("/refresh", async (req, res) => {
  const { token } = req.body;
  if (!token) {
    return res.status(401).json({ message: "no refresh token" });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
    console.log(decoded);
    const profile = await profiles.findById(decoded.id);

    if (!profile) {
      return res.status(403).json({ message: "Invalid refresh token" });
    }

    const newAccessToken = jwt.sign(
      { id: profile._id, role: profile.role },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: "10min" }
    );

    res.status(200).json({ accessToken: newAccessToken });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

router.delete("/:id", verifyToken, async (req, res) => {
  const { id, role } = req.params;
  if (role !== "admin") {
    return res
      .status(403)
      .json({ message: `access denied because you are a ${role}` });
  }
  await profiles.findByIdAndDelete(id);
  res.status(200).json({ message: `obiect with id ${id} has been deleted` });
});

router.put("/:id", verifyToken, async (req, res) => {
  if (req.profile.role !== "admin") {
    return res.status(403).json({
      message: `access denied because your are a ${req.profile.role}`,
    });
  }
  let { name, role, imageUrl } = req.body;

  let userRole = "user";
  if (role !== "admin") {
    role = userRole;
  }
  await profiles.findByIdAndUpdate(
    req.params.id,
    { name, role, imageUrl },
    { new: true }
  );
  res
    .status(200)
    .json({ message: `object with id: ${req.params.id} is edited` });
});

// GET a single profile by ID — Only admin can access
router.get("/profile/:id", verifyToken, async (req, res) => {
  try {
    // Ensure only admin can access
    if (req.profile.role !== "admin") {
      return res.status(403).json({
        message: `access denied because you are a ${req.profile.role}`,
      });
    }

    const profile = await profiles.findById(
      req.params.id,
      "-password -refreshToken"
    );
    if (!profile) {
      return res.status(404).json({ message: "profile not found" });
    }

    res.status(200).json(profile);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

export default router;
