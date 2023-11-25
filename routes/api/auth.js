import express from "express";
import userController from "../../controllers/auth-controller.js";

const authRouter = express.Router();

authRouter.post("/register", userController.signup);
authRouter.post("/login", userController.login);

export default authRouter;
