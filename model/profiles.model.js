import mongoose from "mongoose";

const profileSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ["user", "admin"], default: "user" },
  imageUrl: { type: String, default: "" },
  refreshToken: { type: String, default: "" },
  
});

const profiles = mongoose.model("profiles", profileSchema);
export default profiles;
