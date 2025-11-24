import { NextFunction, Response } from "express"
import { Roles } from "../models/userModel"
import { AuthRequest } from "./auth"

export const requireRole = (roles: Roles[]) => {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({
        message: "Unauthorized"
      })
    }

    const hasRole = roles.some((role) => req.user.roles?.includes(role))
    if (!hasRole) {
      return res.status(403).json({
        message: `Require ${roles} role`
      })
    }
    next()
  }
}