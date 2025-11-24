import { Router } from "express"
import { getAllPost, getMyPost, savePost } from "../controllers/postController"
import { authenticate } from "../middlewares/auth"
import { requireRole } from "../middlewares/role"
import { Roles } from "../models/userModel"
import { upload } from "../middlewares/upload"

const route = Router()

route.post(
  "/create",
  authenticate,
  requireRole([Roles.ADMIN, Roles.AUTHOR]),
  upload.single("image"), // form data key name
  savePost
)

route.get("/", getAllPost)

route.get(
  "/me",
  authenticate,
  requireRole([Roles.ADMIN, Roles.AUTHOR]),
  getMyPost
)

export default route