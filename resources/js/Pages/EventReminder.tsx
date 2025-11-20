import { usePage } from '@inertiajs/react'
import React, { useState, useEffect } from 'react'

type Props = {}

const EventReminder = (props: Props) => {
    const { start_date, lobby_name } = usePage().props as any
    const [timeLeft, setTimeLeft] = useState({
        days: 0,
        hours: 0,
        minutes: 0,
        seconds: 0
    })
    const [expired, setExpired] = useState(false)

    useEffect(() => {
        if (!start_date) return

        const updateCountdown = () => {
            const now = new Date().getTime()
            const start = new Date(start_date).getTime()
            const difference = start - now

            if (difference <= 0) {
                setExpired(true)
                setTimeLeft({ days: 0, hours: 0, minutes: 0, seconds: 0 })
                // Reload page to check if event has started
                setTimeout(() => {
                    window.location.reload()
                }, 1000)
                return
            }

            const days = Math.floor(difference / (1000 * 60 * 60 * 24))
            const hours = Math.floor((difference % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60))
            const minutes = Math.floor((difference % (1000 * 60 * 60)) / (1000 * 60))
            const seconds = Math.floor((difference % (1000 * 60)) / 1000)

            setTimeLeft({ days, hours, minutes, seconds })
        }

        // Update immediately
        updateCountdown()

        // Update every second
        const interval = setInterval(updateCountdown, 1000)

        return () => clearInterval(interval)
    }, [start_date])

    return (
        <div
            className="min-h-screen w-full bg-cover bg-center flex items-start justify-center relative"
            style={{
                backgroundImage: "url('/images/bgonly.png')",
            }}
        >

            <div className="bg-gradient-to-br w-1/2 mt-56 from-red-100 via-red-50 to-red-100 min-h-[400px] flex items-center justify-between p-8 rounded-3xl shadow-2xl relative overflow-hidden">
                {/* Background pattern */}
                <div className="absolute inset-0 opacity-5">
                    <div className="absolute top-10 left-10 w-20 h-20 bg-orange-400 rounded-full"></div>
                    <div className="absolute bottom-20 left-20 w-12 h-12 bg-yellow-400 rounded-full"></div>
                    <div className="absolute top-20 right-32 w-8 h-8 bg-red-400 rounded-full"></div>
                </div>

                {/* Left content */}
                <div className="flex-1 z-10">
                    {/* Logo/brand */}
                    <div className="flex items-center gap-3 mb-8">
                        <div className="w-8 h-8 bg-gradient-to-br from-orange-400 to-red-500 rounded-lg flex items-center justify-center">
                            <svg className="w-5 h-5 text-white" fill="currentColor" viewBox="0 0 20 20">
                                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-12a1 1 0 10-2 0v4a1 1 0 00.293.707l2.828 2.829a1 1 0 101.415-1.415L11 9.586V6z" clipRule="evenodd" />
                            </svg>
                        </div>
                        <span className="text-amber-800 font-medium text-lg">Event Information</span>
                    </div>

                    {/* Main title */}
                    <div className="mb-6">
                        <h1 className="text-6xl font-bold text-amber-900 leading-tight mb-2">
                            Event
                        </h1>
                        <div className="inline-block bg-amber-900 text-white px-6 py-3 text-6xl font-bold rounded-lg shadow-lg">
                            Reminder
                        </div>
                    </div>

                    {/* Lobby Name */}
                    {lobby_name && (
                        <div className="mb-4">
                            <p className="text-amber-800 text-2xl font-bold bg-white/50 backdrop-blur-sm px-4 py-2 rounded-lg inline-block shadow-sm">
                                {lobby_name}
                            </p>
                        </div>
                    )}

                    {/* Countdown Timer */}
                    {!expired ? (
                        <div className="mb-6">
                            <p className="text-amber-700 text-lg font-medium mb-3">Event will start in:</p>
                            <div className="flex gap-4">
                                {/* Days */}
                                <div className="bg-white/80 backdrop-blur-sm px-6 py-4 rounded-lg shadow-lg text-center min-w-[100px]">
                                    <div className="text-4xl font-bold text-amber-900">{timeLeft.days}</div>
                                    <div className="text-sm text-amber-700 font-medium mt-1">Days</div>
                                </div>
                                {/* Hours */}
                                <div className="bg-white/80 backdrop-blur-sm px-6 py-4 rounded-lg shadow-lg text-center min-w-[100px]">
                                    <div className="text-4xl font-bold text-amber-900">{timeLeft.hours}</div>
                                    <div className="text-sm text-amber-700 font-medium mt-1">Hours</div>
                                </div>
                                {/* Minutes */}
                                <div className="bg-white/80 backdrop-blur-sm px-6 py-4 rounded-lg shadow-lg text-center min-w-[100px]">
                                    <div className="text-4xl font-bold text-amber-900">{timeLeft.minutes}</div>
                                    <div className="text-sm text-amber-700 font-medium mt-1">Minutes</div>
                                </div>
                                {/* Seconds */}
                                <div className="bg-white/80 backdrop-blur-sm px-6 py-4 rounded-lg shadow-lg text-center min-w-[100px]">
                                    <div className="text-4xl font-bold text-amber-900">{timeLeft.seconds}</div>
                                    <div className="text-sm text-amber-700 font-medium mt-1">Seconds</div>
                                </div>
                            </div>
                        </div>
                    ) : (
                        <div className="mb-6">
                            <p className="text-amber-800 text-xl font-medium bg-white/50 backdrop-blur-sm px-4 py-2 rounded-lg inline-block shadow-sm">
                                Event is starting...
                            </p>
                        </div>
                    )}

                    {/* Subtitle */}
                    <p className="text-amber-700 text-lg font-medium">
                        Don't miss your important events
                    </p>
                </div>

                {/* Right 3D illustration */}
                <div className="relative z-10 ml-8">
                    {/* 3D Clock with envelope */}
                    <div className="relative">
                        {/* Envelope base */}
                        <div className="w-48 h-32 bg-gradient-to-br from-orange-400 via-orange-500 to-orange-600 rounded-2xl shadow-2xl transform rotate-12 relative">
                            {/* Envelope flap */}
                            <div className="absolute -top-4 left-4 right-4 h-16 bg-gradient-to-br from-orange-300 to-orange-400 rounded-t-2xl shadow-lg transform -rotate-12"></div>

                            {/* Envelope details */}
                            <div className="absolute bottom-4 right-4 w-12 h-3 bg-gradient-to-r from-blue-400 to-blue-500 rounded-full shadow-md"></div>
                            <div className="absolute bottom-8 left-6 right-6 h-2 bg-orange-300/50 rounded-full"></div>
                            <div className="absolute bottom-12 left-6 right-8 h-2 bg-orange-300/30 rounded-full"></div>
                        </div>

                        {/* 3D Clock */}
                        <div className="absolute -top-8 -right-4 w-24 h-24 bg-gradient-to-br from-blue-400 via-blue-500 to-blue-600 rounded-full shadow-2xl border-4 border-white/30">
                            {/* Clock face */}
                            <div className="absolute inset-2 bg-gradient-to-br from-blue-300 to-blue-400 rounded-full flex items-center justify-center">
                                {/* Clock hands */}
                                <div className="absolute w-6 h-0.5 bg-white rounded-full transform -rotate-45 origin-left"></div>
                                <div className="absolute w-4 h-0.5 bg-white/80 rounded-full transform rotate-90 origin-left"></div>
                                {/* Center dot */}
                                <div className="w-2 h-2 bg-white rounded-full shadow-sm"></div>
                            </div>

                            {/* 3D depth effect */}
                            <div className="absolute inset-0 bg-gradient-to-bl from-transparent via-transparent to-blue-700/30 rounded-full"></div>
                        </div>

                        {/* Floating elements */}
                        <div className="absolute -top-12 left-8 w-3 h-3 bg-yellow-400 rounded-full shadow-lg animate-bounce"></div>
                        <div className="absolute top-4 -left-6 w-2 h-2 bg-red-400 rounded-full shadow-lg animate-pulse"></div>
                        <div className="absolute -bottom-4 left-12 w-4 h-4 bg-green-400 rounded-full shadow-lg animate-bounce" style={{ animationDelay: '0.5s' }}></div>
                    </div>
                </div>
            </div>
            <div className="absolute bottom-0 left-0 right-0">
                <img
                    src="/images/icons/footer.png"
                    alt="Footer"
                    className="w-full"
                />
            </div>
        </div>

    )
}

export default EventReminder