import mongoose from "mongoose";

const UserSchema = new mongoose.Schema(
  {
    firstName: { type: String },
    lastName: { type: String },
    username: { type: String },
    email: { type: String },
    accessGroups: { type: String},
    password: { type: String },
  },
  {
    timestamps: true,
    versionKey: false,
    collection: "users",
  }
);

const UserModel = mongoose.model("User", UserSchema);

export default UserModel;
