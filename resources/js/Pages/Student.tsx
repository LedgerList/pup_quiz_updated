import Footer from "@/CustomComponents/Footer";
import React, { useState, useEffect } from "react";
import axios from "axios";
import Swal from "sweetalert2";
import { Eye, EyeOff } from "lucide-react";

type Props = {};

interface PasswordStrength {
    score: number;
    label: string;
    color: string;
    isStrong: boolean;
    suggestions: string[];
}

const Form = (props: Props) => {
    const [currentStep, setCurrentStep] = useState(0);
    const [formData, setFormData] = useState({
        fullName: "",
        studentNumber: "",
        program: "",
        section: "",
        username: "",
        email: "",
        password: "",
    });

    interface FormField {
        name: keyof typeof formData;
        label: string;
        type: string;
        placeholder?: string;
    }

    const [passwordStrength, setPasswordStrength] = useState<PasswordStrength | null>(null);
    const [showPasswordError, setShowPasswordError] = useState(false);
    const [showPassword, setShowPassword] = useState<boolean>(false);

    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        setFormData({ ...formData, [e.target.name]: e.target.value });

        // Reset password error when user starts typing password again
        if (e.target.name === 'password') {
            setShowPasswordError(false);
        }
    };

    const analyzePasswordStrength = (password: string): PasswordStrength => {
        if (!password) {
            return {
                score: 0,
                label: '',
                color: '',
                isStrong: false,
                suggestions: []
            };
        }

        let score = 0;
        const suggestions: string[] = [];

        // Length checks (minimum 8, bonus for 12+)
        if (password.length >= 8) {
            score += 2;
        } else {
            suggestions.push('Use at least 8 characters');
        }

        if (password.length >= 12) {
            score += 1;
        } else if (password.length >= 8) {
            suggestions.push('Consider using 12+ characters for better security');
        }

        // Character variety checks
        if (/[a-z]/.test(password)) {
            score += 1;
        } else {
            suggestions.push('Include lowercase letters (a-z)');
        }

        if (/[A-Z]/.test(password)) {
            score += 1;
        } else {
            suggestions.push('Include uppercase letters (A-Z)');
        }

        if (/[0-9]/.test(password)) {
            score += 1;
        } else {
            suggestions.push('Include numbers (0-9)');
        }

        if (/[^a-zA-Z0-9]/.test(password)) {
            score += 1;
        } else {
            suggestions.push('Include special characters (!@#$%^&*)');
        }

        // Pattern checks
        if (!/(.)\1{2,}/.test(password)) {
            score += 1;
        } else {
            suggestions.push('Avoid repeating the same character 3+ times');
        }

        if (!/123|abc|qwerty|password|admin|user/i.test(password)) {
            score += 1;
        } else {
            suggestions.push('Avoid common patterns and dictionary words');
        }

        // Determine strength level and if it's acceptable
        let label: string;
        let color: string;
        let isStrong: boolean;

        if (score <= 3) {
            label = 'Very Weak';
            color = '#dc2626'; // red-600
            isStrong = false;
        } else if (score <= 4) {
            label = 'Weak';
            color = '#ea580c'; // orange-600
            isStrong = false;
        } else if (score <= 6) {
            label = 'Fair';
            color = '#d97706'; // amber-600
            isStrong = false;
        } else if (score <= 7) {
            label = 'Good';
            color = '#16a34a'; // green-600
            isStrong = true;
        } else {
            label = 'Strong';
            color = '#059669'; // emerald-600
            isStrong = true;
        }

        return { score, label, color, isStrong, suggestions };
    };

    useEffect(() => {
        if (formData.password) {
            const strength = analyzePasswordStrength(formData.password);
            setPasswordStrength(strength);
        } else {
            setPasswordStrength(null);
        }
    }, [formData.password]);

    const generateStrongPassword = () => {
        const lowercase = 'abcdefghijklmnopqrstuvwxyz';
        const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        const numbers = '0123456789';
        const symbols = '!@#$%^&*';

        let password = '';

        // Ensure at least one character from each category
        password += lowercase[Math.floor(Math.random() * lowercase.length)];
        password += uppercase[Math.floor(Math.random() * uppercase.length)];
        password += numbers[Math.floor(Math.random() * numbers.length)];
        password += symbols[Math.floor(Math.random() * symbols.length)];

        // Fill the rest randomly (total 14 characters for extra strength)
        const allChars = lowercase + uppercase + numbers + symbols;
        for (let i = 4; i < 14; i++) {
            password += allChars[Math.floor(Math.random() * allChars.length)];
        }

        // Shuffle the password
        return password.split('').sort(() => Math.random() - 0.5).join('');
    };

    const handlePasswordSuggestion = () => {
        const suggestedPassword = generateStrongPassword();

        Swal.fire({
            title: 'Strong Password Suggestion',
            html: `
        <div style="text-align: left; margin: 20px 0;">
          <p style="margin-bottom: 15px;">Here's a strong password for you:</p>
          <div style="
            background: #f3f4f6; 
            padding: 12px; 
            border-radius: 8px; 
            font-family: monospace; 
            font-size: 16px; 
            font-weight: bold;
            word-break: break-all;
            border: 2px dashed #6b7280;
            margin-bottom: 15px;
          ">
            ${suggestedPassword}
          </div>
          <p style="font-size: 14px; color: #6b7280;">
            💡 This password meets all security requirements and will be accepted immediately.
          </p>
        </div>
      `,
            showCancelButton: true,
            confirmButtonText: 'Use This Password',
            cancelButtonText: 'Generate Another',
            showDenyButton: true,
            denyButtonText: 'Close',
            confirmButtonColor: '#16a34a',
            cancelButtonColor: '#6b7280',
            denyButtonColor: '#dc2626',
        }).then((result) => {
            if (result.isConfirmed) {
                setFormData({ ...formData, password: suggestedPassword });
                setShowPasswordError(false);
            } else if (result.dismiss === Swal.DismissReason.cancel) {
                handlePasswordSuggestion(); // Generate another
            }
        });
    };

    const showToast = (icon: 'success' | 'error', title: string) => {
        Swal.fire({
            toast: true,
            position: 'top-end',
            icon,
            title,
            showConfirmButton: false,
            timer: 3000,
            timerProgressBar: true,
        });
    };

    const canProceedToNextStep = () => {
        // Check if all fields in current step are filled
        const currentFields = steps[currentStep].fields;
        const isAllFieldsFilled = currentFields.every(field =>
            formData[field.name as keyof typeof formData].trim() !== ''
        );

        // If we're on the password step, also check password strength
        if (currentStep === 1) {
            const hasPasswordField = currentFields.some(field => field.name === 'password');
            if (hasPasswordField && passwordStrength) {
                return isAllFieldsFilled && passwordStrength.isStrong;
            }
        }

        return isAllFieldsFilled;
    };

    const handleNext = () => {
        // Check if password is weak on the password step
        if (currentStep === 1 && formData.password && passwordStrength && !passwordStrength.isStrong) {
            setShowPasswordError(true);
            showToast("error", "Please create a stronger password before proceeding");
            return;
        }

        if (currentStep < steps.length - 1) {
            setCurrentStep(currentStep + 1);
        } else {
            handleSubmit();
        }
    };

    const handleSubmit = async () => {
        // Final check before submission
        if (passwordStrength && !passwordStrength.isStrong) {
            showToast("error", "Please create a stronger password before registering");
            return;
        }

        try {
            const response = await axios.post("/register-student", formData);

            showToast("success", "Registration successful! Please login to continue.");
            setTimeout(() => {
                window.location.href = '/login';
            }, 2000);

            console.log(response.data);
        } catch (error: any) {
            if (error.response && error.response.status === 422) {
                const errors = error.response.data.errors;
                const messages = Object.values(errors).flat().join("\n");
                showToast("error", messages);
            } else {
                showToast("error", "Registration failed. Please try again.");
            }
            console.error(error.response?.data || error.message);
        }
    };

    const steps: { fields: FormField[] }[] = [
        {
            fields: [
                { name: "fullName", label: "Full Name", type: "text", placeholder: "Last Name, First Name M.I" },
                { name: "studentNumber", label: "Student Number", type: "text", placeholder: "e.g., 2021-000000-TG-0" },
                { name: "program", label: "Program", type: "text", placeholder: "e.g., BS in Information Technology" },
                { name: "section", label: "Section", type: "text", placeholder: "e.g., BSIT 1-1" },
            ],
        },
        {
            fields: [
                { name: "username", label: "Username", type: "text", placeholder: "Enter your preferred username" },
                { name: "email", label: "Email", type: "email", placeholder: "name@example.com" },
                { name: "password", label: "Password", type: "password", placeholder: "Use 12+ characters with symbols" },
            ],
        },
    ];

    return (
        <div className="min-h-screen flex items-center justify-center">
            <div className="max-w-md w-full px-6 py-8">
                <div className="w-full h-2 rounded-full bg-transparent">
                    <div
                        className="h-full rounded-full"
                        style={{
                            backgroundColor: "#FF2C19",
                            width: `${(currentStep / (steps.length - 1)) * 100}%`,
                        }}
                    ></div>
                </div>

                <div className="bg-transparent rounded-lg p-8 shadow-lg">
                    <h2 className="text-2xl font-bold text-center mb-2">Create an account</h2>
                    <p className="text-gray-600 text-center mb-8">Please enter your details.</p>

                    <form className="space-y-6" style={{ zIndex: 1000 }} onSubmit={(e) => e.preventDefault()}>
                        {steps[currentStep].fields.map((field) => (
                            <div key={field.name} className="relative z-50">
                                <label className="block text-red-500 text-lg mb-1" htmlFor={field.name}>
                                    {field.label}
                                </label>

                                <div className="relative">
                                    <input
                                        type={field.type === "password" && showPassword ? "text" : field.type}
                                        id={field.name}
                                        name={field.name}
                                        value={formData[field.name as keyof typeof formData]}
                                        onChange={handleChange}
                                        className="w-full border-0 border-b border-red-500 pb-2 text-lg focus:ring-0 focus:outline-none focus:border-b-2 bg-transparent pr-10"
                                        placeholder={field.placeholder ?? ""}
                                    />

                                    {/* 👁️ Password toggle button */}
                                    {field.name === "password" && (
                                        <button
                                            type="button"
                                            onClick={() => setShowPassword((prev) => !prev)}
                                            className="absolute right-0 top-1/2 -translate-y-1/2 text-gray-600 hover:text-gray-800 focus:outline-none"
                                        >
                                            {showPassword ? <EyeOff size={20} /> : <Eye size={20} />}
                                        </button>
                                    )}
                                </div>

                                {/* Password Strength Indicator */}
                                {field.name === "password" && formData.password && passwordStrength && (
                                    <div className="mt-3" style={{ zIndex: 100 }}>
                                        {/* Strength Label and Score */}
                                        <div className="flex items-center justify-between mb-2">
                                            <span className="text-sm font-medium text-gray-700">
                                                Password Strength:
                                            </span>
                                            <span
                                                className="text-sm font-bold"
                                                style={{ color: passwordStrength.color }}
                                            >
                                                {passwordStrength.label}
                                            </span>
                                        </div>

                                        {/* Strength Bar */}
                                        <div className="w-full bg-gray-200 rounded-full h-2 mb-3">
                                            <div
                                                className="h-2 rounded-full transition-all duration-300"
                                                style={{
                                                    width: `${(passwordStrength.score / 9) * 100}%`,
                                                    backgroundColor: passwordStrength.color,
                                                }}
                                            ></div>
                                        </div>

                                        {/* Error Message for Weak Password */}
                                        {!passwordStrength.isStrong && showPasswordError && (
                                            <div className="mb-3 p-3 bg-red-50 border border-red-200 rounded-lg">
                                                <p className="text-red-700 text-sm font-medium mb-1">
                                                    ⚠️ Password is too weak for registration
                                                </p>
                                                <p className="text-red-600 text-xs">
                                                    You must create a stronger password to continue.
                                                </p>
                                            </div>
                                        )}

                                        {/* Suggestions */}
                                        {passwordStrength.suggestions.length > 0 && (
                                            <div className="mb-3 p-3 bg-gray-50 rounded-lg border">
                                                <p className="text-gray-700 text-sm font-medium mb-2">
                                                    {passwordStrength.isStrong
                                                        ? "✅ Great password!"
                                                        : "💡 To make your password stronger:"}
                                                </p>
                                                {!passwordStrength.isStrong && (
                                                    <ul className="space-y-1">
                                                        {passwordStrength.suggestions.slice(0, 4).map((suggestion, index) => (
                                                            <li key={index} className="text-sm text-gray-600 flex items-start">
                                                                <span className="w-1 h-1 bg-gray-400 rounded-full mr-2 mt-2 flex-shrink-0"></span>
                                                                {suggestion}
                                                            </li>
                                                        ))}
                                                    </ul>
                                                )}
                                            </div>
                                        )}

                                        {/* Generate Strong Password Button */}
                                        {!passwordStrength.isStrong && (
                                            <button
                                                type="button"
                                                onClick={handlePasswordSuggestion}
                                                style={{ zIndex: 100 }}
                                                className="text-sm bg-green-100 text-green-700 hover:bg-green-200 px-3 py-2 rounded-lg transition-colors border border-green-200"
                                            >
                                                🔐 Generate Strong Password
                                            </button>
                                        )}
                                    </div>
                                )}
                            </div>
                        ))}

                        <div className="flex justify-between pt-8">
                            {currentStep > 0 && (
                                <button
                                    type="button"
                                    onClick={() => setCurrentStep(currentStep - 1)}
                                    style={{ zIndex: 100 }}
                                    className="text-gray-600 hover:text-gray-800"
                                >
                                    Previous
                                </button>
                            )}
                            <button
                                type="button"
                                style={{ zIndex: 100 }}
                                onClick={handleNext}
                                disabled={!canProceedToNextStep()}
                                className={`ml-auto px-8 py-3 rounded-full transition-colors ${canProceedToNextStep()
                                        ? 'bg-red-500 text-white hover:bg-red-600'
                                        : 'bg-gray-300 text-gray-500 cursor-not-allowed'
                                    }`}
                            >
                                {currentStep === steps.length - 1 ? "Sign Up" : "Continue"}
                            </button>
                        </div>
                    </form>
                </div>
            </div>
            <Footer />
        </div>
    );
};

export default Form;
