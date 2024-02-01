import { getToken } from 'next-auth/jwt'
import type { JWT } from 'next-auth'
import { type NextRequest, NextResponse } from 'next/server'

export async function middleware(req: NextRequest) {
    const token = (await getToken({
        req,
        secret: process.env.NEXTAUTH_SECRET!,
    })) as JWT | null

    const { pathname } = req.nextUrl
    const user = token?.user
    const isAuthenticated = !!user

    return NextResponse.next()
}

export const config = {
    matcher: ['/((?!.+\\.[\\w]+$|_next).*)', '/', '/(api|trpc)(.*)'],
}
