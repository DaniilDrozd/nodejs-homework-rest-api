require("dotenv").config();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { HttpError, ctrlWrapper } = require("../helpers");
const { User } = require("../models/users");
const fs = require("fs").promises;
const path = require("path");
const Jimp = require("jimp");
const gravatar = require("gravatar");
const crypto = require("node:crypto");
const sendEmail = require("../helpers/sendEmail");
const register = async (req, res, next) => {
  const { name, email, password } = req.body;
  const user = await User.findOne({ email });
  if (user) {
    throw HttpError(409, `User with ${email} already registered`);
  }
  const PasswordHash = await bcrypt.hash(password, 10);
  const verifyToken = crypto.randomUUID();
  const avatarURL = gravatar.url(email);

  const newUser = await User.create({
    ...req.body,
    verifyToken,
    password: PasswordHash,
    avatar: avatarURL,
  });

  await sendEmail({
    to: email,
    subject: "Confirm email",
    html: `To confirm your registration click on the link: <a href="http://localhost:3000/api/auth/verify/${verifyToken}">link</a>`,
    text: `To confirm your registration open the link http://localhost:3000/api/auth/verify/${verifyToken}`,
  });

  res.status(201).json({
    email: newUser.email,
    name: newUser.name,
  });
};

const login = async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) {
    throw HttpError(401, "Email or password is incorrect");
  }
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    throw new HttpError(401, "Email or password is incorrect");
  }

  if (!user.verify) {
    throw HttpError(401, " Your email is not verified");
  }
  const token = jwt.sign(
    { id: user._id, name: user.name },
    process.env.JWT_SEACRET,
    { expiresIn: "1days" }
  );
  await User.findByIdAndUpdate(user._id, { token });
  res.json({
    token,
    user: { email: user.email, name: user.name },
  });
};

const logout = async (req, res) => {
  await User.findByIdAndUpdate(req.user, { token: null });
  res.status(204).json({
    message: "You are logged out",
  });
};
async function verifyEmail(req, res, next) {
  const { token } = req.params;
  try {
    const user = await User.findOne({ verifyToken: token }).exec();

    if (!user) {
      throw new HttpError(404, "User not found");
    }
    User.findByIdAndUpdate(user._id, { verify: true, verifyToken: null });

    res.send({ message: "Email confirm succesfull" });
  } catch (error) {
    next(error);
  }
}

const verifyAgainEmail = async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user) {
    throw HttpError(404, "Email not found");
  }
  if (user.verify) {
    throw HttpError(400, "Verification has already been passed");
  }
  await sendEmail({
    to: email,
    subject: "Confirm email",
    html: `To confirm your registration click on the link: <a href="http://localhost:3000/api/auth/verify/${verifyToken}">link</a>`,
    text: `To confirm your registration open the link http://localhost:3000/api/auth/verify/${verifyToken}`,
  });
};
const current = async (req, res) => {
  const { email, name } = req.user;
  res.json({ email, name });
};

async function uploadAvatar(req, res, next) {
  try {
    if (req.file === undefined) {
      throw HttpError(404, "You must add an avatar");
    }
    const avatarPath = path.join(
      __dirname,
      "../",
      "public/avatars",
      req.file.filename
    );
    const avatar = await Jimp.read(req.file.path);
    avatar.resize(250, 250).quality(60).write(avatarPath);
    await fs.unlink(
      req.file.path,
      path.join(__dirname, "../", "public/avatars", req.file.filename)
    );

    await User.findByIdAndUpdate(req.user.id, { avatar: req.file.filename });
    res.send("Avatar uploaded successfully");
  } catch (error) {
    next(error);
  }
}

module.exports = {
  register: ctrlWrapper(register),
  login: ctrlWrapper(login),
  current: ctrlWrapper(current),
  logout: ctrlWrapper(logout),
  uploadAvatar: ctrlWrapper(uploadAvatar),
  verifyEmail: ctrlWrapper(verifyEmail),
  verifyAgainEmail: ctrlWrapper(verifyAgainEmail),
};
