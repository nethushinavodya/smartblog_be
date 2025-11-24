import { Request, Response } from "express";
import { Roles, User, Status, IUser } from "../models/userModel";
import bcrypt from "bcryptjs";
import { signAccessToken, signRefreshToken } from "../utils/token";
import { AuthRequest } from "../middlewares/auth";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();

const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET as string;

export const register = async (req: Request, res: Response) => {
  try {
    const { firstname, lastname, email, password, roles } = req.body;

    //  Validate input
    if (!firstname || !lastname || !email || !password || !roles) {
      return res.status(400).json({ message: "Invalid data" });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    //  Role validation & status selection
//  Role validation & status selection
    if (![Roles.USER, Roles.AUTHOR].includes(roles)) {
      return res.status(400).json({ message: "Invalid role" });
    }

    let status = Status.PENDING;
    if (roles === Roles.USER) {
      status = Status.APPROVED;
    } else if (roles === Roles.AUTHOR) {
      status = Status.PENDING; // you can change to APPROVED if authors don’t need review
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // 5 Create user
    const user = await User.create({
      firstName: firstname,
      lastName: lastname,
      email,
      password: hashedPassword,
      roles: [roles],
      status,
    });
    // Return response
    return res.status(201).json({
      message: "User created successfully",
      user: user,
    });

  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Internal server error" });
  }
};

export const login = async (req:Request, res:Response) => {
  try {
    const { email, password } = req.body;

    //  Validate input
    if (!email || !password) {
      return res.status(400).json({ message: "Invalid data" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const accessToken = signAccessToken(user);
    const refreshToken = signRefreshToken(user);
    return res.status(200).json({ 
      message: "Login successful",
      data: {
        email: user.email,
        roles: user.roles,
        accessToken,
        refreshToken
      }
     });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Internal server error" });
  }
}

export const handleRefreshToken = async (req:Request, res:Response) => {
  try {
    const {token} = req.body;
    if(!token){
      return res.status(401).json({message:"Token Required"});
    }
    const payload = jwt.verify(token, JWT_REFRESH_SECRET);
    // payload.sub -> user id
    const user = await User.findById(payload.sub);
    // if user not found
    if(!user){
      return res.status(401).json({message:"User not found"});
    }
    const accessToken = signAccessToken(user);
    return res.status(200).json({message:"Token refreshed", accessToken});
  } catch (error) {
    res.status(403).json({message:"Invalid or Expire token"});
  }
}
export const registerAdmin = async(req:Request, res:Response) => {
  try {
    const { firstname, lastname, email, password } = req.body;

    // 1 Validate input
    if (!firstname || !lastname || !email || !password) {
      return res.status(400).json({ message: "Invalid data" });
    }

    //  Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    //  Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    //  Create user
    const user = await User.create({
      firstName: firstname,
      lastName: lastname,
      email,
      password: hashedPassword,
      roles: [Roles.ADMIN],
      status: Status.APPROVED,
    });
    // 7️⃣ Return response
    return res.status(201).json({
      message: "User created successfully",
      user: user,
    });

  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Internal server error" });
  }
}

export const myProfile = async (req:AuthRequest, res:Response) => {
    if (!req.user) {
    return res.status(401).json({ message: "Unauthorized" })
  }
  const user = await User.findById(req.user.sub).select("-password")

  if (!user) {
    return res.status(404).json({
      message: "User not found"
    })
  }

  const { _id, email, roles, status, firstName, lastName } = user as IUser

  res.status(200).json({ message: "ok", data: { id: _id, email, roles, status, firstName, lastName } })
}

