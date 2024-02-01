import {
    type NextAuthOptions,
    type DefaultSession,
    getServerSession,
    User,
} from 'next-auth'
import { PrismaAdapter } from '@next-auth/prisma-adapter'
import { prisma } from '@/server/db'
import CredentialsProvider from 'next-auth/providers/credentials'
import { compare } from 'bcrypt'
import { loginSchema } from '@/schemas/auth-schemas'

declare module 'next-auth' {
    interface Session extends DefaultSession {
        user: {
            id: string
            email: string
            name: string
        } & DefaultSession['user']
    }
    interface User {
        id: string
        email: string
        name: string
    }
    interface JWT {
        user: {
            id: string
            email: string
            name: string
        } & DefaultSession['user']
    }
}

export const authOptions: NextAuthOptions = {
    secret: process.env.NEXTAUTH_SECRET!,
    adapter: PrismaAdapter(prisma),
    providers: [
        CredentialsProvider({
            name: 'Credentials',
            credentials: {
                email: {
                    type: 'email',
                },
                password: { type: 'password' },
            },
            async authorize(credentials) {
                const validCredentials = loginSchema.safeParse(credentials)

                if (!validCredentials.success) {
                    throw new Error('Invalid credentials')
                }

                const { email, password } = validCredentials.data

                const user = await prisma.user.findUnique({
                    where: { email: email.toLowerCase() },
                })

                if (!user) {
                    throw new Error('Invalid Email')
                }

                const isValid = await compare(password, user.password)
                if (!isValid) {
                    throw new Error('Invalid password')
                }

                return {
                    id: user.id,
                    email: user.email,
                    name: user.name,
                    role: user.role,
                }
            },
        }),
    ],
    pages: {
        signIn: '/login',
    },
    session: {
        strategy: 'jwt',
        maxAge: 30 * 24 * 60 * 60,
    },
    callbacks: {
        async jwt({ token, user }) {
            if (user) {
                token.user = user
            }
            return token
        },
        async session({ session, token }) {
            const user = token.user as User

            return {
                ...session,
                user: {
                    id: user.id,
                    email: user.email,
                    name: user.name,
                    image: user.image,
                },
            }
        },
    },
}

export const getServerAuthSession = () => getServerSession(authOptions)
