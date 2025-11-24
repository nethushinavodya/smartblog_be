import mongoose ,  { Document , Schema} from "mongoose";

export enum Roles {
    USER = "USER",
    ADMIN = "ADMIN",
    AUTHOR = "AUTHOR"
}

export enum Status {
    PENDING = "PENDING",
    APPROVED = "APPROVED",
    REJECTED = "REJECTED"
}
export interface IUser extends Document {
    _id: mongoose.Types.ObjectId;
    firstName: string;
    lastName: string;
    email: string;
    password: string;
    roles: Roles[]
    status: Status;
}

const userSchema = new Schema<IUser>({
    firstName: {
        type: String,
        required: true
    },
    lastName: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    roles: {
        type: [String],
        enum: Object.values(Roles),
        default: [Roles.USER]
    },
    status: {
        type: String,
        enum: Object.values(Status),
        default: Status.PENDING
    }
});

export const User = mongoose.model<IUser>("User", userSchema); 


