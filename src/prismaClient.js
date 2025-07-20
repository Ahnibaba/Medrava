import { PrismaClient } from '@prisma/client';
import { withAccelerate } from '@prisma/extension-accelerate';

// Initialize with Accelerate
const prisma = new PrismaClient().$extends(withAccelerate());

export default prisma;