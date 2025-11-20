import React, { useState } from 'react';
import { X, Shield, ArrowRight, Smartphone, CheckCircle } from 'lucide-react';
import {
    InputOTP,
    InputOTPGroup,
    InputOTPSlot,
} from '@/Components/ui/input-otp';
import { router, usePage } from '@inertiajs/react';
import { PageProps } from '@/types';
import axios from 'axios';

// Modern glassmorphic dialog components
const Dialog = ({ open, onOpenChange, children }) => {
    if (!open) return null;

    return (
        <div className="fixed inset-0 z-[9999] flex items-center justify-center p-4">
            <div
                className="fixed inset-0 bg-white backdrop-blur-md"
                onClick={() => onOpenChange(false)}
            />
            <div className="relative z-[10000] animate-in fade-in-0 zoom-in-95 duration-300">
                {children}
            </div>
        </div>
    );
};

const DialogContent = ({ children, className = "" }) => (
    <div className={`
    bg-white/90 backdrop-blur-xl border border-white/20 rounded-2xl shadow-2xl 
    max-w-md w-full p-8 relative overflow-hidden
    before:absolute before:inset-0 before:bg-gradient-to-br before:from-orange-50/50 before:to-purple-50/30 before:rounded-2xl
    ${className}
  `}>
        <div className="relative z-10">
            {children}
        </div>
    </div>
);

const DialogHeader = ({ children }) => (
    <div className="flex flex-col items-center text-center mb-8">
        {children}
    </div>
);

const DialogTitle = ({ children }) => (
    <h2 className="text-2xl font-bold bg-gradient-to-r from-gray-900 to-gray-600 bg-clip-text text-transparent">
        {children}
    </h2>
);

const DialogDescription = ({ children }) => (
    <p className="text-gray-600 leading-relaxed max-w-sm mx-auto">
        {children}
    </p>
);

const Button = ({ children, onClick, variant = "default", size = "default", className = "", disabled = false }) => {
    const baseClasses = `
    inline-flex items-center justify-center rounded-xl text-sm font-semibold 
    transition-all duration-200 focus:outline-none focus:ring-4 focus:ring-orange-500/20 
    disabled:opacity-50 disabled:pointer-events-none transform active:scale-95
  `;

    const variants = {
        default: `
      bg-gradient-to-r from-orange-500 to-orange-600 text-white 
      hover:from-orange-600 hover:to-orange-700 hover:shadow-lg hover:shadow-orange-500/25
      border border-orange-500/20
    `,
        outline: "border-2 border-gray-200 bg-white/80 hover:bg-gray-50 text-gray-900 hover:border-gray-300",
        ghost: "hover:bg-gray-100/80 text-gray-900"
    };

    const sizes = {
        default: "h-12 px-6 py-3",
        sm: "h-10 px-4",
        icon: "h-12 w-12"
    };

    return (
        <button
            className={`${baseClasses} ${variants[variant]} ${sizes[size]} ${className}`}
            onClick={onClick}
            disabled={disabled}
        >
            {children}
        </button>
    );
};

interface Props {

    isOpen: boolean,
    setIsOpen: (arg1: boolean) => void
}
export default function OTPModal(props: Props) {
    const { isOpen, setIsOpen } = props

    // const [isOpen, setIsOpen] = useState(false);
    const [otpValue, setOtpValue] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState('');
    const [resendTimer, setResendTimer] = useState(0);
    const [isSuccess, setIsSuccess] = useState(false);

    const handleSubmit = async () => {
        if (otpValue.length !== 6) {
            setError('Please enter all 6 digits');
            return;
        }

        setIsLoading(true);
        setError('');

        // Simulate API call
        try {
            const formData = new FormData()
            formData.append("otp", otpValue)
            formData.append("email", localStorage.getItem("email"))
            const response = await axios.post("/verifyOtp", formData)
            console.log(response.data)

            if (response.data.success) {
                localStorage.removeItem("email");
                setIsSuccess(true);

                const notification = document.createElement('div');
                notification.className = 'fixed top-4 right-4 bg-green-500 text-white px-4 py-2 rounded-lg shadow-lg z-50';
                notification.textContent = response.data.success;
                document.body.appendChild(notification);
                setTimeout(() => notification.remove(), 3000);
                
                // Redirect to dashboard after 2 seconds
                setTimeout(() => {
                    router.visit('/dashboard');
                }, 2000);
            }

        } catch (e: any) {
            let errorMessage = 'Verification failed. Please try again.';
            
            if (e.response?.data?.error) {
                errorMessage = e.response.data.error;
            } else if (e.response?.data?.message) {
                errorMessage = e.response.data.message;
            } else if (e.message) {
                errorMessage = e.message;
            } else if (!e.response) {
                errorMessage = 'Unable to connect to server. Please check your connection.';
            }
            
            setError(errorMessage);
            
            // Show subtle notification instead of alert
            const notification = document.createElement('div');
            notification.className = 'fixed top-4 right-4 bg-red-500 text-white px-4 py-2 rounded-lg shadow-lg z-50';
            notification.textContent = errorMessage;
            document.body.appendChild(notification);
            setTimeout(() => notification.remove(), 3000);
        } finally {
            setIsLoading(false);
        }
    };

    const handleResend = async () => {
        setResendTimer(30);
        setError('');
        setOtpValue('');



        try {
            const formData = new FormData()
            formData.append("email", localStorage.getItem("email"))
            const response = await axios.post("/resendOTP", formData)


            if (response.data.success) {

                // Show subtle notification instead of alert
                const notification = document.createElement('div');
                notification.className = 'fixed top-4 right-4 bg-green-500 text-white px-4 py-2 rounded-lg shadow-lg z-50';
                notification.textContent = response.data.success;
                document.body.appendChild(notification);
                setTimeout(() => notification.remove(), 3000);

            }

        } catch (e: any) {
            let errorMessage = 'Failed to resend OTP. Please try again.';
            
            if (e.response?.data?.error) {
                errorMessage = e.response.data.error;
            } else if (e.response?.data?.message) {
                errorMessage = e.response.data.message;
            } else if (e.message) {
                errorMessage = e.message;
            } else if (!e.response) {
                errorMessage = 'Unable to connect to server. Please check your connection.';
            }
            
            setError(errorMessage);
            
            // Show subtle notification instead of alert
            const notification = document.createElement('div');
            notification.className = 'fixed top-4 right-4 bg-red-500 text-white px-4 py-2 rounded-lg shadow-lg z-50';
            notification.textContent = errorMessage;
            document.body.appendChild(notification);
            setTimeout(() => notification.remove(), 3000);
        } finally {
            // Countdown timer
            const interval = setInterval(() => {
                setResendTimer(prev => {
                    if (prev <= 1) {
                        clearInterval(interval);
                        return 0;
                    }
                    return prev - 1;
                });
            }, 1000);
        }

    };

    const isComplete = otpValue.length === 6;

    return (
        <div >


            <Dialog open={isOpen} onOpenChange={() => { }}>
                <DialogContent

                >
                    {!isSuccess ? (
                        <>
                            <button
                                onClick={() => { }}
                                className="absolute right-4 top-4 rounded-full p-2 opacity-70 hover:opacity-100 hover:bg-gray-100/80 transition-all focus:outline-none focus:ring-2 focus:ring-orange-500/20"
                            >
                                <X className="h-4 w-4" />
                            </button>

                            <DialogHeader>
                                <div className="relative mb-6">
                                    <div className="w-16 h-16 bg-gradient-to-br from-orange-500 to-orange-600 rounded-2xl flex items-center justify-center shadow-lg shadow-orange-500/25 mb-4">
                                        <Smartphone className="w-8 h-8 text-white" />
                                    </div>
                                    <div className="absolute -bottom-1 -right-1 w-6 h-6 bg-green-500 rounded-full flex items-center justify-center">
                                        <div className="w-2 h-2 bg-white rounded-full"></div>
                                    </div>
                                </div>

                                <DialogTitle>Verify Your Email</DialogTitle>
                                <DialogDescription>
                                    Enter the 6-digit verification code sent to your email address ending in <span className="font-semibold text-gray-900">{localStorage.getItem("email")}</span>
                                </DialogDescription>
                            </DialogHeader>

                            <div className="space-y-8">
                                <div className="space-y-4">
                                    <div className="flex justify-center">
                                        <InputOTP
                                            maxLength={6}
                                            value={otpValue}
                                            onChange={(value) => setOtpValue(value)}
                                        >
                                            <InputOTPGroup className="gap-3">
                                                {[0, 1, 2, 3, 4, 5].map((index) => (
                                                    <InputOTPSlot
                                                        key={index}
                                                        index={index}
                                                        className="
                              w-12 h-14 text-lg font-bold rounded-xl border-2 
                              border-gray-200 bg-white/80 backdrop-blur-sm
                              focus:border-orange-500 focus:ring-4 focus:ring-orange-500/20 
                              data-[filled=true]:border-orange-400 data-[filled=true]:bg-orange-50/50
                              transition-all duration-200 shadow-sm
                              hover:border-orange-300 hover:shadow-md
                            "
                                                    />
                                                ))}
                                            </InputOTPGroup>
                                        </InputOTP>
                                    </div>

                                    {error && (
                                        <div className="bg-red-50 border border-red-200 rounded-xl p-3 animate-in slide-in-from-top-1">
                                            <p className="text-sm text-red-700 text-center font-medium">{error}</p>
                                        </div>
                                    )}
                                </div>

                                <Button
                                    onClick={handleSubmit}
                                    disabled={!isComplete || isLoading}
                                    className="w-full h-14 text-base font-semibold"
                                >
                                    {isLoading ? (
                                        <div className="flex items-center gap-3">
                                            <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                                            <span>Verifying...</span>
                                        </div>
                                    ) : (
                                        <div className="flex items-center gap-3">
                                            <span>Verify & Continue</span>
                                            <ArrowRight className="w-5 h-5" />
                                        </div>
                                    )}
                                </Button>

                                <div className="text-center border-t border-gray-200/60 pt-6">
                                    <p className="text-sm text-gray-500 mb-3">
                                        Didn't receive the code?
                                    </p>
                                    {resendTimer > 0 ? (
                                        <div className="flex items-center justify-center gap-2 text-orange-600 font-medium">
                                            <div className="w-4 h-4 border-2 border-orange-600 border-t-transparent rounded-full animate-spin"></div>
                                            <span>Resend in {resendTimer}s</span>
                                        </div>
                                    ) : (
                                        <button
                                            onClick={handleResend}
                                            className="inline-flex items-center gap-2 text-orange-600 hover:text-orange-700 font-semibold text-sm bg-orange-50 hover:bg-orange-100 px-4 py-2 rounded-lg transition-colors"
                                        >
                                            <Smartphone className="w-4 h-4" />
                                            Send New Code
                                        </button>
                                    )}
                                </div>
                            </div>
                        </>
                    ) : (
                        <div className="text-center py-8 space-y-6">
                            <div className="w-20 h-20 bg-gradient-to-br from-green-500 to-green-600 rounded-full flex items-center justify-center mx-auto animate-in zoom-in-50 duration-500">
                                <CheckCircle className="w-10 h-10 text-white" />
                            </div>
                            <div>
                                <DialogTitle>
                                    <p className="text-green-600 mb-2">
                                        Verification Successful!
                                    </p>
                                </DialogTitle>
                                <p className="text-gray-600">
                                    Your email has been verified. Redirecting to dashboard...
                                </p>
                            </div>
                            <Button
                                className="w-full h-12 text-base font-semibold"
                                onClick={() => {
                                    setIsOpen(false);
                                    router.visit('/dashboard');
                                }}
                            >
                                <span>Go to Dashboard</span>
                                <ArrowRight className="w-5 h-5 ml-2" />
                            </Button>
                        </div>
                    )}
                </DialogContent>
            </Dialog>
        </div>
    );
}