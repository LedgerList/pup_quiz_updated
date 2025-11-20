import Checkbox from '@/Components/Checkbox';
import InputError from '@/Components/InputError';
import InputLabel from '@/Components/InputLabel';
import PrimaryButton from '@/Components/PrimaryButton';
import TextInput from '@/Components/TextInput';
import { Button } from '@/Components/ui/button';
import Footer from '@/CustomComponents/Footer';
import OTPModal from '@/CustomComponents/OTPModal';
import GuestLayout from '@/Layouts/GuestLayout';

import { Head, Link, router, useForm } from '@inertiajs/react';
import axios from 'axios';
import { Eye, EyeOff, Home } from 'lucide-react';
import { FormEventHandler, useState } from 'react';
import Swal from 'sweetalert2';
import 'sweetalert2/dist/sweetalert2.min.css';

export default function Login({
    status,
    canResetPassword,
}: {
    status?: string;
    canResetPassword: boolean;
}) {
    const { data, setData, post, processing, errors, reset } = useForm({
        email: '',
        password: '',
        remember: false as boolean,
    });
    const [showPassword, setShowPassword] = useState<boolean>(false)
    const [openOTPModal, setOpenOTPModal] = useState(false)
    const submit: FormEventHandler = async (e) => {
        e.preventDefault();

        try {
            // 🟡 First query — check account before login
            const response = await axios.post(route('login-info'), { email: data.email });

            const first_login = response.data.exist

            post(first_login ? route('login') : route('otp-login'), {
                onFinish: () => reset('password'),
                onSuccess: () => {

                    if (!first_login) {
                        setOpenOTPModal(true); localStorage.setItem("email", data.email)
                    }

                },
                onError: (errors) => {
                    // If backend sent JSON with "msg"
                    let message = "Incorrect email or password";

                    // Inertia puts plain JSON under errors.response if it's not a validation error
                    if (errors && typeof errors === "object") {
                        if (errors.msg) {
                            message = errors.msg;
                        }
                    }

                    Swal.fire({
                        toast: true,
                        position: 'top-end',
                        icon: 'error',
                        title: message,
                        showConfirmButton: false,
                        timer: 3000,
                        timerProgressBar: true,
                        background: '#fff',
                        color: '#e3342f',
                        iconColor: '#e3342f',
                    });
                },
            });
        }
        catch (error) {
            // 🔴 Handle network or backend error
            Swal.fire({
                toast: true,
                position: 'top-end',
                icon: 'error',
                title: 'Server error while checking account',
                showConfirmButton: false,
                timer: 3000,
                timerProgressBar: true,
                background: '#fff',
                color: '#e3342f',
                iconColor: '#e3342f',
            });
        }
    };

    return (
        <GuestLayout>
            <Head title="Log in" />

            <OTPModal isOpen={openOTPModal} setIsOpen={setOpenOTPModal} />
            {status && (
                <div className="mb-4 text-sm font-medium text-green-600">
                    {status}
                </div>
            )}

            <form onSubmit={submit} style={{ zIndex: 10 }} className="z-50 bg-transparent p-8 rounded-3xl shadow-lg max-w-md w-full mx-auto">
                {/* Red accent line at the top */}
                <div className="w-full h-2 bg-[#FF2C19] rounded-full mb-8"></div>

                <h2 className="text-2xl font-bold text-gray-800 mb-2 text-center">Login</h2>
                <p className="text-gray-500 text-sm mb-8 text-center">Please enter your details.</p>

                <div className="space-y-6">
                    <div>
                        <InputLabel htmlFor="email" value="Email" className="text-red-600 text-base font-bold" />
                        <TextInput
                            id="email"
                            type="email"
                            name="email"
                            value={data.email}
                            className="mt-1 block w-full border-0 border-b border-red-600 focus:border-red-500 focus:ring-0 bg-transparent px-0 text-gray-700 rounded-none hover:bg-slate-200 transition-colors"
                            autoComplete="username"
                            isFocused={true}
                            onChange={(e) => setData('email', e.target.value)}
                            placeholder="name@example.com"
                        />
                    </div>

                    {/* <div>
                        <InputLabel htmlFor="password" value="Password" className="text-red-600 text-base font-bold" />
                        <TextInput
                            id="password"
                            type="password"
                            name="password"
                            value={data.password}
                            className="mt-1 block w-full border-0 border-b border-red-600 focus:border-red-500 focus:ring-0 bg-transparent px-0 text-gray-700 rounded-none hover:bg-slate-200 transition-colors"
                            autoComplete="current-password"
                            onChange={(e) => setData('password', e.target.value)}
                        />
                        <InputError message={errors.password} className="mt-2" />
                    </div> */}
                    <div className="relative">
                        <InputLabel
                            htmlFor="password"
                            value="Password"
                            className="text-red-600 text-base font-bold"
                        />
                        <div className="relative">
                            <TextInput
                                id="password"
                                type={showPassword ? 'text' : 'password'}
                                name="password"
                                value={data.password}
                                className="mt-1 block w-full border-0 border-b border-red-600 focus:border-red-500 focus:ring-0 bg-transparent px-0 text-gray-700 rounded-none hover:bg-slate-200 transition-colors pr-10"
                                autoComplete="current-password"
                                onChange={(e) => setData('password', e.target.value)}
                            placeholder="Enter your password"
                            />
                            <button
                                type="button"
                                onClick={() => setShowPassword(!showPassword)}
                                className="absolute right-0 top-1/2 -translate-y-1/2 text-gray-600 hover:text-gray-800 focus:outline-none"
                            >
                                {showPassword ? <EyeOff size={20} /> : <Eye size={20} />}
                            </button>
                        </div>
                        <InputError message={errors.password} className="mt-2" />
                    </div>

                    <div className="flex items-center justify-between">
                        <label className="flex items-center">
                            <Checkbox
                                name="remember"
                                checked={data.remember}
                                onChange={(e) => setData('remember', e.target.checked)}
                                className="border-gray-300 text-[#FF2C19] focus:ring-[#FF2C19]"
                            />
                            <span className="ms-2 text-sm text-gray-600">
                                Remember me
                            </span>
                        </label>

                        {canResetPassword && (
                            <Link
                                href={route('password.request')}
                                className="text-sm text-[#FF2C19] hover:text-[#e52913] transition-colors"
                            >
                                Forgot password?
                            </Link>
                        )}
                    </div>
                    <div className='flex justify-center flex-col items-center gap-y-5'>
                        <PrimaryButton
                            className=" w-4/5 bg-red-600 text-white px-8 py-4 rounded-[50px] hover:bg-red-600 transition-colors mt-8 text-xl font-semibold text-center flex justify-center items-center"
                            style={{
                                boxShadow: '0px 8px 15px rgba(249, 115, 22, 0.35)',
                                filter: 'drop-shadow(0px 4px 4px rgba(0, 0, 0, 0.15))',
                                zIndex: 10,
                            }}
                            disabled={processing}
                        >
                            Login
                        </PrimaryButton>

                        <Button className=" w-4/5 px-8 py-4 flex items-center justify-center gap-x-3" variant={"link"} type={"button"}
                            onClick={() =>
                                router.get("/")
                            }>
                            <Home />
                            Home
                        </Button>
                    </div>

                </div>
            </form>

            <div style={{ zIndex: 100 }}>
                <Footer />
            </div>



        </GuestLayout>
    );
}
