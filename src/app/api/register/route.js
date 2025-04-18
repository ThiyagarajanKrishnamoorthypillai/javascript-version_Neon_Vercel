import { NextResponse } from 'next/server'
import bcrypt from 'bcryptjs'
import { prisma } from '@/libs/prisma' // adjust if your path is different


export async function POST(req) {
  const body = await req.json()
  const { username, email, password } = body

  if (!username || !email || !password) {
    return NextResponse.json({ message: 'Missing fields' }, { status: 400 })
  }

  try {
    const existingUser = await prisma.user.findUnique({
      where: { email }
    })

    if (existingUser) {
      return NextResponse.json({ message: 'User already exists' }, { status: 409 })
    }

    const hashedPassword = await bcrypt.hash(password, 10)

    const newUser = await prisma.user.create({
      data: {
        name: username,
        email,
        password: hashedPassword
      }
    })

    return NextResponse.json({ success: true, user: newUser })
  } catch (error) {
    console.error('[REGISTER_ERROR]', error)
    return NextResponse.json({ message: 'Server error' }, { status: 500 })
  }
}
