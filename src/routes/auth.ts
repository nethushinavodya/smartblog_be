import { Router } from "express"
import {
  myProfile,
  login,
  register,
  registerAdmin,
  handleRefreshToken
} from "../controllers/authController"
import { authenticate } from "../middlewares/auth"
import { requireRole } from "../middlewares/role"
import { Roles } from "../models/userModel"

const router = Router()

router.post("/register", register)
router.post("/login", login)
router.get("/me", authenticate, myProfile)
router.post("/admin/register",authenticate,requireRole([Roles.ADMIN]),registerAdmin)
router.post("/refresh", handleRefreshToken)
export default router