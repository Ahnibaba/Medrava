/*
  Warnings:

  - Added the required column `forgot_password_expire_time` to the `users` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "users" ADD COLUMN     "forgot_password_expire_time" TIMESTAMP(3) NOT NULL,
ADD COLUMN     "forgot_password_otp" TEXT NOT NULL DEFAULT '';
