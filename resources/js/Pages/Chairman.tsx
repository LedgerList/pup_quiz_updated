import Footer from "@/CustomComponents/Footer";
import React, { useState } from "react";

type Props = {};

const Form = (props: Props) => {
    const [currentStep, setCurrentStep] = useState(0);
    const [formData, setFormData] = useState({
        fullName: "",
        department: "",
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

    const steps: { fields: FormField[] }[] = [
        {
            fields: [
                { name: "fullName", label: "Full Name", type: "text", placeholder: "Last Name, First Name MI" },
                { name: "department", label: "Department", type: "text", placeholder: "E.g., College of Engineering" },
               
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
        <div className="min-h-screen flex items-center justify-center ">
            <div className="max-w-md w-full px-6 py-8">
                {/* Progress Bar */}
                {/* <div className="mb-12 relative flex justify-between">
                    <div className="absolute top-4 left-0 right-0 h-[2px] bg-gray-200">
                        <div
                            className="h-full bg-red-500 transition-all duration-300"
                            style={{
                                width: `${
                                    (currentStep / (steps.length - 1)) * 100
                                }%`,
                            }}
                        />
                    </div>
                    {steps.map((_, index) => (
                        <div key={index} className="relative z-10">
                            <div
                                className={`
                                w-8 h-8 rounded-full flex items-center justify-center
                                ${
                                    index <= currentStep
                                        ? "bg-red-500"
                                        : "bg-gray-200"
                                }
                                text-white font-medium transition-all duration-300
                            `}
                            >
                                {index + 1}
                            </div>
                        </div>
                    ))}
                </div> */}
                {/* Loading Bar */}
                <div className="w-[100%] lg:w-[100%] mx-auto  lg:mb-6 mt-4 lg:mt-6">
                    <div className="w-full h-2 rounded-full bg-transparent">
                        <div
                            className="h-full rounded-full"
                            style={{
                                backgroundColor: "#FF2C19",
                                width: `${(currentStep / 2) * 100}%`,
                            }}
                        ></div>
                    </div>
                </div>
                {/* Form Content */}
                <div className="bg-transparent rounded-lg p-8 shadow-lg">
                    <h2 className="text-2xl font-bold text-center mb-2">
                        Create an account
                    </h2>
                    <p className="text-gray-600 text-center mb-8">
                        Please enter your details.
                    </p>

                    <form className="space-y-6" style={{ zIndex: 1000 }}>
                        {steps[currentStep].fields.map((field) => (
                            <div key={field.name} className="relative">
                                <label
                                    className="block text-red-500 text-lg mb-1"
                                    htmlFor={field.name}
                                >
                                    {field.label}
                                </label>
                                <input
                                    type={field.type}
                                    id={field.name}
                                    name={field.name}
                                    value={
                                        formData[
                                            field.name as keyof typeof formData
                                        ]
                                    }
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
                                    onClick={() =>
                                        setCurrentStep(currentStep - 1)
                                    }
                                    style={{zIndex:100}}
                                    className="text-gray-600 hover:text-gray-800"
                                >
                                    Previous
                                </button>
                            )}
                            <button
                                type="button"
                                style={{zIndex:100}}
                                onClick={() => {
                                    if (currentStep < steps.length - 1) {
                                        setCurrentStep(currentStep + 1);
                                    } else {
                                        // Handle form submission
                                        console.log(
                                            "Form submitted:",
                                            formData
                                        );
                                    }
                                }}
                                className="ml-auto bg-red-500 text-white px-8 py-3 rounded-full hover:bg-red-600 transition-colors"
                            >
                                {currentStep === steps.length - 1
                                    ? "Sign Up"
                                    : "Continue"}
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
