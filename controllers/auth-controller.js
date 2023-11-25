import User from "../models/User.js";
import Joi from "joi";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import "dotenv/config";

const userSchema = Joi.object({
  email: Joi.string().required(),
  password: Joi.string().required(),
});

const { JWT_SECRET } = process.env;

const signup = async (req, res, next) => {
  try {
    const userValidate = userSchema.validate(req.body);
    if (userValidate.error) {
      const error = new Error(userValidate.error.message);
      error.status = 400;
      throw error;
    }
    const user = await User.findOne({ email: req.body.email });
    if (user) {
      const error = new Error("Email in use");
      error.status = 409;
      throw error;
    }
    const hashPassword = await bcrypt.hash(req.body.password, 10);

    const newUser = await User.create({
      ...req.body,
      password: hashPassword,
    });
    res.status(201).json({
      user: {
        email: newUser.email,
        subscription: newUser.subscription,
      },
    });
  } catch (error) {
    next(error);
  }
};

const login = async (req, res, next) => {
  try {
    const userValidate = userSchema.validate(req.body);
    if (userValidate.error) {
      const error = new Error(userValidate.error.message);
      error.status = 400;
      throw error;
    }
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      const error = new Error("Email or password is wrong");
      error.status = 401;
      throw error;
    }
    const comparePassword = await bcrypt.compare(
      req.body.password,
      user.password
    );
    if (!comparePassword) {
      const error = new Error("Email or password is wrong");
      error.status = 401;
      throw error;
    }
    const payload = {
      id: user._id,
    };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "23h" });
    res.json({
      token,
      user: {
        email: user.email,
        subscription: user.subscription,
      },
    });
  } catch (error) {
    next(error);
  }
};

export default {
  signup,
  login,
};
