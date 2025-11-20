// import Footer from "@/CustomComponents/Footer";
// import { Link } from "@inertiajs/react";
// import { useState } from "react";

// type Option = {
//     id: string;
//     label: string;
//     icon: string;
//     color: string;
//     href?: string; // Make href optional
// };

// type Props = {};

// const GetStarted = (props: Props) => {
//     const [currentStep, setCurrentStep] = useState(0);
//     const [setupType, setSetupType] = useState<"class" | "event" | null>(null);

//     const stepTitles = [
//         "Describe a setup that suits you",
//         "What type of account would you like to create?",
//     ];

//     const stepOptions: Option[][] = [
//         [
//             {
//                 id: "class",
//                 label: "Class",
//                 icon: "/images/icons/icon1.png",
//                 color: "bg-blue-500",
//             },
//             {
//                 id: "event",
//                 label: "Event",
//                 icon: "/images/icons/icon2.png",
//                 color: "bg-emerald-500",
//             },
//         ],
//         setupType === "class"
//             ? [
//                   {
//                       id: "teacher",
//                       label: "Teacher",
//                       icon: "/images/icons/icon3.png",
//                       color: "bg-teal-500",
//                       href: "/teacher",
//                   },
//                   {
//                       id: "student",
//                       label: "Student",
//                       icon: "/images/icons/icon4.png",
//                       color: "bg-red-400",
//                       href: "/student",
//                   },
//               ]
//             : [
//                   {
//                       id: "participant",
//                       label: "Participant",
//                       icon: "/images/icons/icon3.png",
//                       color: "bg-purple-500",
//                       href: "/participant",
//                   },
//                   {
//                       id: "Organizer",
//                       label: "Organizer",
//                       icon: "/images/icons/icon4.png",
//                       color: "bg-yellow-400",
//                       href: "/organizer",
//                   },
//               ],
//     ];

//     return (
//         <div className="min-h-screen py-12 px-4 bg-gray-100">
//             <div className="max-w-4xl mx-auto">
//                 {/* Progress Bar */}
//                 <div className="w-full lg:mb-6 mt-4 lg:mt-6">
//                     <div className="w-full h-2 rounded-full bg-gray-300">
//                         <div
//                             className="h-full rounded-full"
//                             style={{
//                                 backgroundColor: "#FF2C19",
//                                 width: `${(currentStep / 1) * 100}%`,
//                             }}
//                         ></div>
//                     </div>
//                 </div>

//                 {/* Step Content */}
//                 <div className="p-8 pt-4">
//                     <h2 className="text-2xl font-bold mb-8 text-gray-800">
//                         {stepTitles[currentStep]}
//                     </h2>

//                     <div className="grid grid-cols-1 gap-6">
//                         {stepOptions[currentStep].map((option) => {
//                             const content = (
//                                 <div className="flex items-center gap-x-4 bg-white rounded-md hover:cursor-pointer">
//                                     <div
//                                         className={`${option.color} p-6 rounded-lg text-white hover:opacity-90 transition-opacity flex flex-col items-center`}
//                                     >
//                                         <img src={option.icon} width={80} />
//                                     </div>
//                                     <span className="text-xl font-semibold">
//                                         {option.label}
//                                     </span>
//                                 </div>
//                             );

//                             if (currentStep === 0) {
//                                 return (
//                                     <div
//                                         key={option.id}
//                                         onClick={() => {
//                                             setSetupType(
//                                                 option.id as "class" | "event"
//                                             );
//                                             setCurrentStep(1);
//                                         }}
//                                     >
//                                         {content}
//                                     </div>
//                                 );
//                             }

//                             // Type Guard: Check if href exists
//                             if (option.href) {
//                                 return (
//                                     <Link key={option.id} href={option.href}>
//                                         {content}
//                                     </Link>
//                                 );
//                             }

//                             return content; // Return without the Link if no href
//                         })}
//                     </div>
//                 </div>

//                 {/* Navigation Buttons */}
//                 <div className="mt-8 flex justify-between">
//                     <button
//                         onClick={() => {
//                             setCurrentStep(Math.max(0, currentStep - 1));
//                         }}
//                         style={{ zIndex: 100 }}
//                         className={`px-6 py-2 rounded-lg ${
//                             currentStep === 0
//                                 ? "invisible"
//                                 : "bg-gray-200 hover:bg-gray-300"
//                         }`}
//                     >
//                         Previous
//                     </button>
//                 </div>

//                 <div className="z-100">
//                     <Footer />
//                 </div>
//             </div>
//         </div>
//     );
// };

// export default GetStarted;
import Footer from "@/CustomComponents/Footer";
import { Link } from "@inertiajs/react";
import { useState } from "react";

type Option = {
    id: string;
    label: string;
    icon: string;
    color: string;
    href?: string; // Make href optional
};

type Props = {};

const GetStarted = (props: Props) => {
    const [currentStep, setCurrentStep] = useState(0);
    const [setupType, setSetupType] = useState<"class" | "event" | null>(null);

    const stepTitles = [
        "Describe a setup that suits you",
        "What type of account would you like to create?",
    ];

    const stepOptions: Option[][] = [
        [
            {
                id: "class",
                label: "Class",
                icon: "/images/icons/icon1.png",
                color: "bg-blue-500",
            },
            {
                id: "event",
                label: "Event",
                icon: "/images/icons/icon2.png",
                color: "bg-emerald-500",
            },
        ],
        setupType === "class"
            ? [
                  {
                      id: "teacher",
                      label: "Teacher",
                      icon: "/images/icons/icon3.png",
                      color: "bg-teal-500",
                      href: "/teacher",
                  },
                  {
                      id: "student",
                      label: "Student",
                      icon: "/images/icons/icon4.png",
                      color: "bg-red-400",
                      href: "/student",
                  },
              ]
            : [
                  {
                      id: "participant",
                      label: "Participant",
                      icon: "/images/icons/icon3.png",
                      color: "bg-purple-500",
                      href: "/participant",
                  },
                  {
                      id: "Organizer",
                      label: "Organizer",
                      icon: "/images/icons/icon4.png",
                      color: "bg-yellow-400",
                      href: "/organizer",
                  },
              ],
    ];

    return (
        <div className="min-h-screen py-12 px-4 bg-gray-100">
            <div className="max-w-4xl mx-auto">
                {/* Home Button */}
                <div className="mb-4">
                    <Link 
                        href="/" 
                        className="inline-flex items-center px-4 py-2 bg-white border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50 transition-colors"
                    >
                        <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
                        </svg>
                        Home
                    </Link>
                </div>

                {/* Progress Bar */}
                <div className="w-full lg:mb-6 mt-4 lg:mt-6">
                    <div className="w-full h-2 rounded-full bg-gray-300">
                        <div
                            className="h-full rounded-full"
                            style={{
                                backgroundColor: "#FF2C19",
                                width: `${(currentStep / 1) * 100}%`,
                            }}
                        ></div>
                    </div>
                </div>

                {/* Step Content */}
                <div className="p-8 pt-4">
                    <h2 className="text-2xl font-bold mb-8 text-gray-800">
                        {stepTitles[currentStep]}
                    </h2>

                    <div className="grid grid-cols-1 gap-6">
                        {stepOptions[currentStep].map((option) => {
                            const content = (
                                <div className="flex items-center gap-x-4 bg-white rounded-md hover:cursor-pointer">
                                    <div
                                        className={`${option.color} p-6 rounded-lg text-white hover:opacity-90 transition-opacity flex flex-col items-center`}
                                    >
                                        <img src={option.icon} width={80} />
                                    </div>
                                    <span className="text-xl font-semibold">
                                        {option.label}
                                    </span>
                                </div>
                            );

                            // if (currentStep === 0) {
                            //     return (
                            //         <div
                            //             key={option.id}
                            //             onClick={() => {
                            //                 setSetupType(
                            //                     option.id as "class" | "event"
                            //                 );
                            //                 setCurrentStep(1);
                            //             }}
                            //         >
                            //             {content}
                            //         </div>
                            //     );
                            // }
                            if (currentStep === 0) {
                                return (
                                    <div
                                        key={option.id}
                                        onClick={() => {
                                            setSetupType(
                                                option.id as "class" | "event"
                                            );
                                            setCurrentStep(1);
                                        }}
                                        className="cursor-pointer hover:shadow-lg transition-shadow duration-300"
                                    >
                                        {content}
                                    </div>
                                );
                            }


                            // Type Guard: Check if href exists
                            if (option.href) {
                                return (
                                    <Link key={option.id} href={option.href}>
                                        {content}
                                    </Link>
                                );
                            }

                            return content; // Return without the Link if no href
                        })}
                    </div>
                </div>

                {/* Navigation Buttons */}
                <div className="mt-8 flex justify-between">
                    <button
                        onClick={() => {
                            setCurrentStep(Math.max(0, currentStep - 1));
                        }}
                        style={{ zIndex: 100 }}
                        className={`px-6 py-2 rounded-lg ${
                            currentStep === 0
                                ? "invisible"
                                : "bg-gray-200 hover:bg-gray-300"
                        }`}
                    >
                        Previous
                    </button>
                </div>

                <div className="z-100">
                    <Footer />
                </div>
            </div>
        </div>
    );
};

export default GetStarted;