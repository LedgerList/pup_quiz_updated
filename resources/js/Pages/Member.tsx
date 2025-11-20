import Footer from "@/CustomComponents/Footer";
import React, { useState } from "react";
import axios from "axios";
import Swal from "sweetalert2";

type Props = {};

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

    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        setFormData({ ...formData, [e.target.name]: e.target.value });
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

    const handleSubmit = async () => {
        try {
            const response = await axios.post("/register-member", formData);
            showToast("success", "Registration successful!");
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
                { name: "fullName", label: "Full Name", type: "text", placeholder: "Last Name, First Name MI" },
                { name: "studentNumber", label: "Student Number", type: "text" },
                { name: "program", label: "Program", type: "text" },
                { name: "section", label: "Section", type: "text" },
            ],
        },
        {
            fields: [
                { name: "username", label: "Username", type: "text" },
                { name: "email", label: "Email", type: "email" },
                { name: "password", label: "Password", type: "password" },
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
                            width: `${(currentStep / 2) * 100}%`,
                        }}
                    ></div>
                </div>

                <div className="bg-transparent rounded-lg p-8 shadow-lg">
                    <h2 className="text-2xl font-bold text-center mb-2">Create an account</h2>
                    <p className="text-gray-600 text-center mb-8">Please enter your details.</p>

                    <form className="space-y-6" style={{ zIndex: 1000 }}>
                        {steps[currentStep].fields.map((field) => (
                            <div key={field.name} className="relative">
                                <label className="block text-red-500 text-lg mb-1" htmlFor={field.name}>
                                    {field.label}
                                </label>
                                <input
                                    type={field.type}
                                    id={field.name}
                                    name={field.name}
                                    value={formData[field.name as keyof typeof formData]}
                                    onChange={handleChange}
                                    className="w-full border-0 border-b border-red-500 pb-2 text-lg focus:ring-0 focus:outline-none focus:border-b-2 bg-transparent"
                                    placeholder={field.placeholder ?? ""}
                                />
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
                                onClick={() => {
                                    if (currentStep < steps.length - 1) {
                                        setCurrentStep(currentStep + 1);
                                    } else {
                                        handleSubmit();
                                    }
                                }}
                                className="ml-auto bg-red-500 text-white px-8 py-3 rounded-full hover:bg-red-600 transition-colors"
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
