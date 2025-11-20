import React, { ChangeEvent, DragEvent, useEffect, useState } from 'react';
import { ChevronRight, ChevronLeft, Check, CheckCircle, Sparkles, Upload, X } from 'lucide-react';
import axios from 'axios';
import Swal from 'sweetalert2';
import Checkbox from '@/Components/Checkbox';

export default function PreRegistrationForm() {
    const [currentStep, setCurrentStep] = useState(0);
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [submitSuccess, setSubmitSuccess] = useState(false);
    const [submitError, setSubmitError] = useState('');
    const [selectedSubjects, setSelectedSubjects] = useState<string[]>([]);

    const [showUploadModalTeamLeader, setShowUploadModalTeamLeader] = useState(false)
    const [formData, setFormData] = useState({
        category: '',
        fullName: '',
        studentNumber: '',
        courseYear: '',
        email: '',
        contactNumber: '',
        teamName: '',
        members: [
            {
                name: '',
                studentNumber: '',
                courseYear: '',
                requirements: {
                    studentId: null,
                    registrationForm: null,
                    consentForm: null
                }
            }
        ],
        validStudentId: null,
        registrationForm: null,
        signedConsentForm: null,
        requirements: false,
        certification: false
    });
    const [formDataDoc, setFormDataDoc] = useState({
        studentId: null as File | null,
        consentForm: null as File | null,
        registrationForm: null as File | null,
        certification: false,
    });
    const [participantId, setParticipantId] = useState(null);
    const [csrfToken, setCsrfToken] = useState<string | null>(null);
    const steps = [
        { id: 1, title: 'Event', description: 'Event Selection' },
        { id: 2, title: 'Details', description: 'Basic Information' },
        { id: 3, title: 'Sub', description: 'Event Category' },
        { id: 4, title: 'Info', description: 'Team Leader Information' },
        { id: 5, title: 'Team', description: 'Team Information ' },

    ];
    useEffect(() => {
        const token = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
        if (token) {
            setCsrfToken(token);
        } else {
            console.error("CSRF token meta tag not found.");
            Swal.fire({
                toast: true,
                position: 'top-end',
                icon: 'error',
                title: 'CSRF token not found. Please refresh the page.',
                showConfirmButton: false,
                timer: 3000,
                timerProgressBar: true,
            });
        }
    }, []);
    const handleInputChange = (e) => {
        const { name, value, type, checked } = e.target;
        setFormData(prev => ({
            ...prev,
            [name]: type === 'checkbox' ? checked : value
        }));
    };

    const handleFileSelect = (
        e: ChangeEvent<HTMLInputElement>,
        field: keyof typeof formDataDoc
    ) => {
        const file = e.target.files?.[0];
        if (file) {
            // Check file size (2MB = 2 * 1024 * 1024 bytes)
            const maxSize = 2 * 1024 * 1024; // 2MB
            if (file.size > maxSize) {
                Swal.fire({
                    icon: 'error',
                    title: 'File Too Large',
                    html: `
                        <div class="text-left">
                            <p class="mb-2">The file <strong>${file.name}</strong> exceeds the maximum size limit.</p>
                            <p class="text-sm text-gray-600">Maximum file size: <strong>2MB</strong></p>
                            <p class="text-sm text-gray-600">Your file size: <strong>${(file.size / 1024 / 1024).toFixed(2)}MB</strong></p>
                        </div>
                    `,
                    confirmButtonColor: '#f97316',
                    confirmButtonText: 'OK',
                    allowOutsideClick: false,
                });
                // Reset the input
                e.target.value = '';
                return;
            }
            setFormDataDoc({ ...formDataDoc, [field]: file });
            
            // Show success alert
            Swal.fire({
                icon: 'success',
                title: 'File Uploaded',
                text: `${file.name} has been uploaded successfully.`,
                timer: 2000,
                showConfirmButton: false,
                toast: true,
                position: 'top-end',
            });
        }
    };

    const handleDrop = (
        e: DragEvent<HTMLDivElement>,
        field: keyof typeof formDataDoc
    ) => {
        e.preventDefault();
        const file = e.dataTransfer.files[0];
        if (file) {
            // Check file size (2MB = 2 * 1024 * 1024 bytes)
            const maxSize = 2 * 1024 * 1024; // 2MB
            if (file.size > maxSize) {
                Swal.fire({
                    icon: 'error',
                    title: 'File Too Large',
                    html: `
                        <div class="text-left">
                            <p class="mb-2">The file <strong>${file.name}</strong> exceeds the maximum size limit.</p>
                            <p class="text-sm text-gray-600">Maximum file size: <strong>2MB</strong></p>
                            <p class="text-sm text-gray-600">Your file size: <strong>${(file.size / 1024 / 1024).toFixed(2)}MB</strong></p>
                        </div>
                    `,
                    confirmButtonColor: '#f97316',
                    confirmButtonText: 'OK',
                    allowOutsideClick: false,
                });
                return;
            }
            setFormDataDoc({ ...formDataDoc, [field]: file });
            
            // Show success alert
            Swal.fire({
                icon: 'success',
                title: 'File Uploaded',
                text: `${file.name} has been uploaded successfully.`,
                timer: 2000,
                showConfirmButton: false,
                toast: true,
                position: 'top-end',
            });
        }
    };

    const handleDragOver = (e: DragEvent<HTMLDivElement>) => {
        e.preventDefault();
    };

    const handleInputChangeDoc = (e: ChangeEvent<HTMLInputElement>) => {
        setFormDataDoc({ ...formDataDoc, [e.target.name]: e.target.checked });
    };
    const handleSubmit = async () => {
        // Prevent duplicate submissions
        if (isSubmitting) {
            return;
        }

        const { studentId, consentForm, registrationForm, certification } = formDataDoc;

        // Check if any file is missing or certification is false
        const isValid =
            studentId !== null &&
            // consentForm !== null &&
            registrationForm !== null

        if (!isValid) {
            Swal.fire({
                icon: "error",
                title: "Missing Documents",
                html: `
                    <div class="text-left">
                        <p class="mb-2">Team Leader documents are required.</p>
                        <p class="text-sm text-gray-600">Please upload:</p>
                        <ul class="text-sm text-gray-600 list-disc list-inside mt-2">
                            <li>Valid Student's ID</li>
                            <li>Certificate of Registration Form</li>
                        </ul>
                    </div>
                `,
                confirmButtonColor: "#f97316",
                allowOutsideClick: false,
            });
            return;
        }
        const allMembersValid = formData.members.every(member =>
            member.name.trim() !== '' &&
            member.studentNumber.trim() !== '' &&
            member.courseYear.trim() !== '' &&
            member.requirements.studentId !== null &&
            member.requirements.registrationForm !== null
           // && member.requirements.consentForm !== null
        );
        if (!allMembersValid) {
            Swal.fire({
                icon: "error",
                title: "Incomplete Information",
                html: `
                    <div class="text-left">
                        <p class="mb-2">All fields are required for each team member.</p>
                        <p class="text-sm text-gray-600">Please ensure:</p>
                        <ul class="text-sm text-gray-600 list-disc list-inside mt-2">
                            <li>Name is filled</li>
                            <li>Student Number is filled</li>
                            <li>Course & Year is filled</li>
                            <li>All required documents are uploaded</li>
                        </ul>
                    </div>
                `,
                confirmButtonColor: "#f97316",
                allowOutsideClick: false,
            });
            return;
        }
        if (!csrfToken) {
            Swal.fire({
                icon: "error",
                title: "Security Error",
                text: "CSRF token not found. Please refresh the page.",
                confirmButtonColor: "#f97316",
                allowOutsideClick: false,
            });
            return;
        }

        // Show confirmation modal before submission
        const confirmResult = await Swal.fire({
            icon: 'question',
            title: 'Confirm Registration',
            html: `
                <div class="text-left">
                    <p class="mb-3">Are you sure you want to submit your registration?</p>
                    <p class="text-sm text-gray-600">Please review all information before proceeding.</p>
                </div>
            `,
            showCancelButton: true,
            confirmButtonColor: '#f97316',
            cancelButtonColor: '#6b7280',
            confirmButtonText: 'Yes, Submit',
            cancelButtonText: 'Cancel',
            allowOutsideClick: false,
        });

        if (!confirmResult.isConfirmed) {
            return;
        }

        setIsSubmitting(true);
        setSubmitError("");

        // Show loading modal
        Swal.fire({
            title: 'Processing Registration',
            html: 'Please wait while we process your registration...',
            allowOutsideClick: false,
            allowEscapeKey: false,
            showConfirmButton: false,
            didOpen: () => {
                Swal.showLoading();
            }
        });

        try {
            const formDataToSend = new FormData();

            // 🔹 Basic team info
            formDataToSend.append("team", formData.teamName);
            formDataToSend.append("team_leader", formData.fullName);
            formDataToSend.append("team_leader_email", formData.email);
            formDataToSend.append("subject", selectedSubjects[0]);
            formDataToSend.append("studentNumber", formData.studentNumber);
            formDataToSend.append("courseYear", formData.courseYear);
            formDataToSend.append("contactNumber", formData.contactNumber);
            formDataToSend.append("lobbyCode", lobbyCode);

            // 🔹 Team leader’s files

            if (formDataDoc.studentId)
                formDataToSend.append("validStudentId", formDataDoc.studentId);
            if (formDataDoc.registrationForm)
                formDataToSend.append("registrationForm", formDataDoc.registrationForm);
            if (formDataDoc.consentForm)
                formDataToSend.append("signedConsentForm", formDataDoc.consentForm);

            // 🔹 Members (loop through each)
            formData.members.forEach((member, index) => {
                formDataToSend.append(`members[${index}][name]`, member.name);
                formDataToSend.append(`members[${index}][studentNumber]`, member.studentNumber);
                formDataToSend.append(`members[${index}][courseYear]`, member.courseYear);

                // Each member's files (if present)
                if (member.requirements.studentId)
                    formDataToSend.append(
                        `members[${index}][studentId]`,
                        member.requirements.studentId
                    );
                if (member.requirements.registrationForm)
                    formDataToSend.append(
                        `members[${index}][registrationForm]`,
                        member.requirements.registrationForm
                    );
                if (member.requirements.consentForm)
                    formDataToSend.append(
                        `members[${index}][consentForm]`,
                        member.requirements.consentForm
                    );
            });

            // 🔹 Send request
            const response = await fetch("/participant", {
                method: "POST",
                headers: {
                    "X-CSRF-TOKEN": csrfToken,
                },
                body: formDataToSend, // ✅ multipart/form-data
            });

            const data = await response.json();

            if (response.ok) {
                // Close loading modal
                Swal.close();
                
                // Show success modal
                await Swal.fire({
                    icon: "success",
                    title: "Registration Successful!",
                    html: `
                        <div class="text-left">
                            <p class="mb-2">Your team has been registered successfully!</p>
                            <p class="text-sm text-gray-600">You will receive a confirmation email shortly.</p>
                        </div>
                    `,
                    confirmButtonColor: "#f97316",
                    allowOutsideClick: false,
                });
                
                setParticipantId(data.user.id);
                setSubmitSuccess(true);
                setCurrentStep(7);
            } else {
                // Close loading modal
                Swal.close();
                
                // Check for duplicate registration error (409 Conflict)
                if (response.status === 409) {
                    Swal.fire({
                        icon: "warning",
                        title: "Already Registered",
                        html: `
                            <div class="text-left">
                                <p class="mb-2">${data.message || "You have already registered for this event."}</p>
                                <p class="text-sm text-gray-600">${data.error || "Each email address and student number can only register once."}</p>
                            </div>
                        `,
                        confirmButtonColor: "#f97316",
                        allowOutsideClick: false,
                    });
                } else {
                    // Show error modal with details
                    let errorMessage = data.message || "Failed to create team";
                    if (data.errors) {
                        const errorList = Object.values(data.errors).flat().join('<br>');
                        errorMessage = `<div class="text-left"><p class="mb-2">${data.message || "Validation errors occurred:"}</p><p class="text-sm text-gray-600">${errorList}</p></div>`;
                    }
                    
                    Swal.fire({
                        icon: "error",
                        title: "Registration Failed",
                        html: errorMessage,
                        confirmButtonColor: "#f97316",
                        allowOutsideClick: false,
                    });
                }
            }
        } catch (error: any) {
            console.error("Error:", error);
            
            // Close loading modal
            Swal.close();
            
            // Show error modal
            Swal.fire({
                icon: "error",
                title: "Registration Error",
                html: `
                    <div class="text-left">
                        <p class="mb-2">An error occurred while processing your registration.</p>
                        <p class="text-sm text-gray-600">${error.message || "Please try again later."}</p>
                    </div>
                `,
                confirmButtonColor: "#f97316",
                allowOutsideClick: false,
            });
            setSubmitError(error.message || "An error occurred. Please try again.");
        } finally {
            setIsSubmitting(false);
        }
    };


    const nextStep = () => {
        if (currentStep < steps.length - 1) {
            setCurrentStep(currentStep + 1);
        }
    };

    const prevStep = () => {
        if (currentStep > 0) {
            setCurrentStep(currentStep - 1);
        }
    };
    const [showUploadModal, setShowUploadModal] = useState(false);
    const [selectedMemberIndex, setSelectedMemberIndex] = useState(null);
    const [showConfetti, setShowConfetti] = useState(false);
    const [isVisible, setIsVisible] = useState(false);
    const [lobbyCode, setLobbyCode] = useState(null)
    const [subjects, setSubjects] = useState([]);

    useEffect(() => {
        setIsVisible(true);
        setTimeout(() => setShowConfetti(true), 500);
    }, []);
    const handleEnterCode = async () => {
        try {
            const response = await axios.get(`/check-lobby-code/${lobbyCode}`)
            localStorage.setItem("event_name", response.data[0].lobby.name)
            setSubjects(response.data)
            setCurrentStep(1)
        } catch (error) {

            if (error.status == 404) {
                Swal.fire({
                    icon: 'error',
                    title: 'Code not Found',
                    text: 'Please get a valid code.',
                    confirmButtonColor: '#f97316',
                });
            }
            console.log(error)
        }
    }
    const openUploadModal = (index) => {
        setSelectedMemberIndex(index);
        setShowUploadModal(true);
    };
    const [agreePrivacy, setAgreePrivacy] = useState<boolean>(
        !!localStorage.getItem("agree_privacy")
    );

    useEffect(() => {
        if (agreePrivacy) {
            localStorage.setItem("agree_privacy", "1");
        } else {
            localStorage.removeItem("agree_privacy");
        }
    }, [agreePrivacy]);
    const renderStepContent = () => {
        switch (currentStep) {

            case 0: return (
                <div>
                    <div className="flex flex-col justify-start text-left gap-y-2">

                        <label className="text-orange-600 font-bold" >Enter Lobby Code</label>
                        <input
                            type="text"
                            placeholder="Lobby Code"
                            value={lobbyCode}
                            onChange={(e) => setLobbyCode(e.target.value)}
                            className="w-full p-3 border border-gray-300 rounded-lg mb-4 text-gray-800"
                            required
                        />
                    </div>
                    <div className="flex gap-3">

                        <button
                            onClick={() => handleEnterCode()}
                            className="flex-1 py-2 px-4 rounded-lg bg-red-600 text-white hover:bg-red-700 transition duration-200"
                        >
                            Continue
                        </button>
                    </div>
                </div>

            )
            case 1:
                return (
                    <div className="space-y-6">
                        <h2 className="text-2xl font-semibold text-gray-800">Participant Registration</h2>

                        <div className="bg-red-50 border-l-4 border-red-500 p-4 rounded">
                            <p className="text-sm text-gray-700">
                                The Quiz Bee Pre-Registration is the first step for participants who wish to join the upcoming PUP-T Quiz Bee. Through this online registration, interested students can sign up early, form their teams, and secure their slots before the event officially begins.
                            </p>
                            <p className="mt-3 text-sm text-gray-700">
                                Please fill out the registration form completely and accurately. Only pre-registered participants will be eligible to join the official elimination rounds. Team assignments and confirmation details will be sent to your registered email once the pre-registration period closes.
                            </p>
                        </div>

                        <div className="space-y-4 text-sm text-gray-600">
                            <h3 className="font-semibold text-gray-800">Data Privacy Notice</h3>
                            <p>
                                By submitting this pre-registration form, you acknowledge and agree to the collection of your personal information for the purpose of organizing and managing the PUP-T Quiz Bee. The data collected will be used solely for event coordination, assessment, and communication purposes, and will not be shared with any third parties without your consent.
                            </p>
                            <p>
                                All information will be stored securely and accessed only by authorized organizers. You have the right to request access, correction, or deletion of your data at any time by contacting the event administrator.
                            </p>
                            <p>
                                By proceeding, you confirm that you have read, understood, and agreed to this Data Privacy Notice in compliance with the Data Privacy Act of 2012 (Republic Act No. 10173).
                            </p>
                        </div>
                        <div className='flex items-center gap-x-3'>
                            <Checkbox
                                id="agree_privacy"
                                checked={agreePrivacy}
                                onClick={() => setAgreePrivacy(!agreePrivacy)}
                                className="text-orange-700"
                            />
                            <p className="text-orange-800">
                                I agree to the Terms and Conditions and Privacy Policy.*
                            </p>
                        </div>


                    </div>

                );

            case 2:
                return (
                    <div className="space-y-6">
                        <h2 className="text-2xl font-semibold text-gray-800">Event Category</h2>
                        <div>
                            <label className="block text-sm font-medium text-gray-700 mb-2">
                                Select Event Category *
                            </label>
                            <select
                                value={selectedSubjects[0] || ''}
                                onChange={(e) => setSelectedSubjects(e.target.value ? [e.target.value] : [])}
                                className="w-full p-3 border border-gray-300 rounded-lg text-gray-800 bg-white"
                                required
                            >
                                <option value="">Choose a subject...</option>
                                {subjects.map((subject) => (
                                    <option key={subject.subject_name} value={subject.subject_name}>
                                        {subject.subject_name}
                                    </option>
                                ))}
                            </select>

                        </div>
                    </div>
                );

            case 3:
                return (
                    <div className="space-y-6">
                        <h2 className="text-2xl font-semibold text-gray-800">Team Leader Information</h2>
                        <div className="space-y-4">
                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-2">
                                    Full Name *
                                </label>
                                <input
                                    type="text"
                                    name="fullName"
                                    value={formData.fullName}
                                    onChange={handleInputChange}
                                    placeholder="(Last Name, First Name, Middle Initial)"
                                    className="w-full px-4 py-3 border border-gray-300 rounded focus:ring-2 focus:ring-red-500 focus:border-transparent"
                                />
                            </div>

                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-2">
                                    Student Number *
                                </label>
                                <input
                                    type="text"
                                    name="studentNumber"
                                    value={formData.studentNumber}
                                    onChange={handleInputChange}
                                    placeholder="(e.g. 2021-12345-MN-0)"
                                    className="w-full px-4 py-3 border border-gray-300 rounded focus:ring-2 focus:ring-red-500 focus:border-transparent"
                                />
                            </div>

                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-2">
                                    Course & Year *
                                </label>
                                <input
                                    type="text"
                                    name="courseYear"
                                    value={formData.courseYear}
                                    onChange={handleInputChange}
                                    placeholder="(e.g. BSIT 3-1)"
                                    className="w-full px-4 py-3 border border-gray-300 rounded focus:ring-2 focus:ring-red-500 focus:border-transparent"
                                />
                            </div>

                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-2">
                                    Email Address *
                                </label>
                                <input
                                    type="email"
                                    name="email"
                                    value={formData.email}
                                    onChange={handleInputChange}
                                    placeholder="example@gmail.com"
                                    className="w-full px-4 py-3 border border-gray-300 rounded focus:ring-2 focus:ring-red-500 focus:border-transparent"
                                />
                            </div>

                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-2">
                                    Contact Number *
                                </label>
                                <input
                                    type="tel"
                                    name="contactNumber"
                                    value={formData.contactNumber}
                                    onChange={handleInputChange}
                                    placeholder="(e.g. +63 XXX XXXX XXX)"
                                    className="w-full px-4 py-3 border border-gray-300 rounded focus:ring-2 focus:ring-red-500 focus:border-transparent"
                                />
                            </div>
                        </div>
                    </div>
                );

            case 4:
                return (
                    // <div className="space-y-6">
                    //     <h2 className="text-2xl font-semibold text-gray-800">Team Information</h2>
                    //     <div className="space-y-4">
                    //         <div>
                    //             <label className="block text-sm font-medium text-gray-700 mb-2">
                    //                 Team Name *
                    //             </label>
                    //             <input
                    //                 type="text"
                    //                 name="teamName"
                    //                 value={formData.teamName}
                    //                 onChange={handleInputChange}
                    //                 placeholder="Team Name"
                    //                 className="w-full px-4 py-3 border border-gray-300 rounded focus:ring-2 focus:ring-red-500 focus:border-transparent"
                    //             />
                    //         </div>

                    //         <div>
                    //             <label className="block text-sm font-medium text-gray-700 mb-2">
                    //                 Members *
                    //             </label>
                    //             <div className="space-y-3">
                    //                 {formData.members.map((member, index) => (
                    //                     <div key={index} className="bg-gray-50 p-4 rounded border border-gray-200">
                    //                         <div className="flex justify-between items-center mb-2">
                    //                             <span className="text-sm font-medium text-gray-700">Member {index + 1}</span>
                    //                             {index > 0 && (
                    //                                 <button
                    //                                     onClick={() => {
                    //                                         const newMembers = formData.members.filter((_, i) => i !== index);
                    //                                         setFormData(prev => ({ ...prev, members: newMembers }));
                    //                                     }}
                    //                                     className="text-red-600 hover:text-red-800 text-sm"
                    //                                 >
                    //                                     Remove
                    //                                 </button>
                    //                             )}
                    //                         </div>
                    //                         <div className="space-y-2">
                    //                             <input
                    //                                 type="text"
                    //                                 placeholder="(Last Name, First Name, Middle Initial)"
                    //                                 value={member.name}
                    //                                 onChange={(e) => {
                    //                                     const newMembers = [...formData.members];
                    //                                     newMembers[index].name = e.target.value;
                    //                                     setFormData(prev => ({ ...prev, members: newMembers }));
                    //                                 }}
                    //                                 className="w-full px-3 py-2 border border-gray-300 rounded focus:ring-2 focus:ring-red-500 focus:border-transparent text-sm"
                    //                             />
                    //                             <input
                    //                                 type="text"
                    //                                 placeholder="(e.g. 2021-12345-MN-0)"
                    //                                 value={member.studentNumber}
                    //                                 onChange={(e) => {
                    //                                     const newMembers = [...formData.members];
                    //                                     newMembers[index].studentNumber = e.target.value;
                    //                                     setFormData(prev => ({ ...prev, members: newMembers }));
                    //                                 }}
                    //                                 className="w-full px-3 py-2 border border-gray-300 rounded focus:ring-2 focus:ring-red-500 focus:border-transparent text-sm"
                    //                             />
                    //                             <input
                    //                                 type="text"
                    //                                 placeholder="(e.g. BSIT 3-1)"
                    //                                 value={member.courseYear}
                    //                                 onChange={(e) => {
                    //                                     const newMembers = [...formData.members];
                    //                                     newMembers[index].courseYear = e.target.value;
                    //                                     setFormData(prev => ({ ...prev, members: newMembers }));
                    //                                 }}
                    //                                 className="w-full px-3 py-2 border border-gray-300 rounded focus:ring-2 focus:ring-red-500 focus:border-transparent text-sm"
                    //                             />
                    //                         </div>
                    //                     </div>
                    //                 ))}
                    //             </div>

                    //             <button
                    //                 onClick={() => {
                    //                     setFormData(prev => ({
                    //                         ...prev,
                    //                         members: [...prev.members, { name: '', studentNumber: '', courseYear: '' }]
                    //                     }));
                    //                 }}
                    //                 className="w-full mt-3 px-4 py-2 bg-gray-200 hover:bg-gray-300 text-gray-700 rounded font-medium transition-colors"
                    //             >
                    //                 Add member
                    //             </button>
                    //         </div>
                    //     </div>
                    // </div>

                    <div className="space-y-6">

                        <h2 className="text-2xl font-semibold text-gray-800">Team Information</h2>

                        <div className="bg-blue-50 border-l-4 border-blue-500 p-4 rounded mb-4">
                            <p className="text-sm text-gray-700 font-medium mb-2">Each member should upload the following:</p>
                            <ul className="text-sm text-gray-700 list-disc list-inside space-y-1">
                                <li>Valid Student's ID</li>
                                <li>Registration Form</li>
                                <li>Signed Consent form (if required)</li>
                                <li>Other requirements (applicable only)</li>
                            </ul>
                        </div>
                        <div className="space-y-4">
                            <div className="flex gap-2">
                                <button
                                    onClick={() => setShowUploadModalTeamLeader(true)}
                                    className="flex items-center gap-1 px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white text-xs rounded transition-colors"
                                >
                                    <Upload className="w-3 h-3" />
                                    Upload Team Leader Requirements
                                </button>
                                {/* {index > 0 && (
                                                        <button
                                                            onClick={() => {
                                                                const newMembers = formData.members.filter((_, i) => i !== index);
                                                                setFormData(prev => ({ ...prev, members: newMembers }));
                                                            }}
                                                            className="text-red-600 hover:text-red-800 text-sm"
                                                        >
                                                            Remove
                                                        </button>
                                                    )} */}
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-2">
                                    Team Name *
                                </label>
                                <input
                                    type="text"
                                    name="teamName"
                                    value={formData.teamName}
                                    onChange={handleInputChange}
                                    placeholder="Team Name"
                                    className="w-full px-4 py-3 border border-gray-300 rounded focus:ring-2 focus:ring-red-500 focus:border-transparent"
                                />
                            </div>

                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-2">
                                    Members *
                                </label>
                                <div className="space-y-3">
                                    {formData.members.map((member, index) => (
                                        <div key={index} className="bg-gray-50 p-4 rounded border border-gray-200">
                                            <div className="flex justify-between items-center mb-2">
                                                <span className="text-sm font-medium text-gray-700">Member {index + 1}</span>
                                                <div className="flex gap-2">
                                                    <button
                                                        onClick={() => openUploadModal(index)}
                                                        className="flex items-center gap-1 px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white text-xs rounded transition-colors"
                                                    >
                                                        <Upload className="w-3 h-3" />
                                                        Upload Requirements
                                                    </button>
                                                    {index > 0 && (
                                                        <button
                                                            onClick={() => {
                                                                const newMembers = formData.members.filter((_, i) => i !== index);
                                                                setFormData(prev => ({ ...prev, members: newMembers }));
                                                            }}
                                                            className="text-red-600 hover:text-red-800 text-sm"
                                                        >
                                                            Remove
                                                        </button>
                                                    )}
                                                </div>
                                            </div>
                                            <div className="space-y-2">
                                                <input
                                                    type="text"
                                                    placeholder="(Last Name, First Name, Middle Initial)"
                                                    value={member.name}
                                                    onChange={(e) => {
                                                        const newMembers = [...formData.members];
                                                        newMembers[index].name = e.target.value;
                                                        setFormData(prev => ({ ...prev, members: newMembers }));
                                                    }}
                                                    className="w-full px-3 py-2 border border-gray-300 rounded focus:ring-2 focus:ring-red-500 focus:border-transparent text-sm"
                                                />
                                                <input
                                                    type="text"
                                                    placeholder="(e.g. 2021-12345-MN-0)"
                                                    value={member.studentNumber}
                                                    onChange={(e) => {
                                                        const newMembers = [...formData.members];
                                                        newMembers[index].studentNumber = e.target.value;
                                                        setFormData(prev => ({ ...prev, members: newMembers }));
                                                    }}
                                                    className="w-full px-3 py-2 border border-gray-300 rounded focus:ring-2 focus:ring-red-500 focus:border-transparent text-sm"
                                                />
                                                <input
                                                    type="text"
                                                    placeholder="(e.g. BSIT 3-1)"
                                                    value={member.courseYear}
                                                    onChange={(e) => {
                                                        const newMembers = [...formData.members];
                                                        newMembers[index].courseYear = e.target.value;
                                                        setFormData(prev => ({ ...prev, members: newMembers }));
                                                    }}
                                                    className="w-full px-3 py-2 border border-gray-300 rounded focus:ring-2 focus:ring-red-500 focus:border-transparent text-sm"
                                                />
                                            </div>
                                            {/* Requirements Status */}
                                            {(member.requirements.studentId || member.requirements.registrationForm || member.requirements.consentForm) && (
                                                <div className="mt-3 pt-3 border-t border-gray-200">
                                                    <p className="text-xs text-gray-600 mb-1">Uploaded Files:</p>
                                                    <div className="flex flex-wrap gap-2">
                                                        {member.requirements.studentId && (
                                                            <span className="text-xs bg-green-100 text-green-700 px-2 py-1 rounded">✓ Student ID</span>
                                                        )}
                                                        {member.requirements.registrationForm && (
                                                            <span className="text-xs bg-green-100 text-green-700 px-2 py-1 rounded">✓ Registration Form</span>
                                                        )}
                                                        {member.requirements.consentForm && (
                                                            <span className="text-xs bg-green-100 text-green-700 px-2 py-1 rounded">✓ Consent Form</span>
                                                        )}
                                                    </div>
                                                </div>
                                            )}
                                        </div>
                                    ))}
                                </div>

                                <button
                                    onClick={() => {
                                        setFormData(prev => ({
                                            ...prev,
                                            members: [...prev.members, {
                                                name: '',
                                                studentNumber: '',
                                                courseYear: '',
                                                requirements: {
                                                    studentId: null,
                                                    registrationForm: null,
                                                    consentForm: null
                                                }
                                            }]
                                        }));
                                    }}
                                    className="w-full mt-3 px-4 py-2 bg-gray-200 hover:bg-gray-300 text-gray-700 rounded font-medium transition-colors"
                                >
                                    Add member
                                </button>
                            </div>
                        </div>
                    </div>
                );


            case 5:
                return (
                    <div className="space-y-6">
                        <h2 className="text-2xl font-semibold text-gray-800">Requirements Submission</h2>

                        <div className="bg-blue-50 border-l-4 border-blue-500 p-4 rounded mb-4">
                            <p className="text-sm text-gray-700 font-medium mb-2">Each member should upload the following:</p>
                            <ul className="text-sm text-gray-700 list-disc list-inside space-y-1">
                                <li>Valid Student's ID</li>
                                <li>Registration Form</li>
                                <li>Signed Consent form (if required)</li>
                                <li>Other requirements (applicable only)</li>
                            </ul>
                        </div>

                        <div className="space-y-4">
                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-2">
                                    Valid Student's ID *
                                </label>
                                <div onDragOver={handleDragOver}
                                    onDrop={(e) => handleDrop(e, "studentId")}
                                    onClick={() => document.getElementById("studentId")?.click()} className="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center bg-gray-50 hover:bg-gray-100 transition-colors cursor-pointer">
                                    <div className="flex flex-col items-center">
                                        <input
                                            id={"studentId"}
                                            type="file"
                                            accept=".pdf,.png,.jpg,.jpeg"
                                            className="hidden"
                                            onChange={(e) => handleFileSelect(e, "studentId")}
                                        />
                                        {/* <div className="w-12 h-12 bg-gray-200 rounded-lg flex items-center justify-center mb-3">
                                            <span className="text-2xl text-gray-400">+</span>
                                        </div> */}
                                        {!formDataDoc.studentId ? (
                                            <div className="flex flex-col items-center">
                                                <div className="w-12 h-12 bg-gray-200 rounded-lg flex items-center justify-center mb-3">
                                                    <span className="text-2xl text-gray-400">+</span>
                                                </div>
                                                <p className="text-sm text-gray-600">Click to upload or drag and drop</p>
                                                <p className="text-xs text-gray-500 mt-1">PDF, PNG, JPG up to 10MB</p>
                                            </div>
                                        ) : (
                                            <div className="flex flex-col items-center space-y-2">
                                                <div className="w-12 h-12 bg-green-100 rounded-lg flex items-center justify-center">
                                                    <span className="text-green-600 text-xl">✔</span>
                                                </div>
                                                <p className="text-sm text-gray-700">{formDataDoc.studentId.name}</p>
                                                <p className="text-xs text-gray-500">{(formDataDoc.studentId.size / 1024 / 1024).toFixed(2)} MB</p>
                                            </div>
                                        )}
                                    </div>
                                </div>
                            </div>

                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-2">
                                    Signed Consent Form *
                                </label>
                                <div onDragOver={handleDragOver}
                                    onDrop={(e) => handleDrop(e, "consentForm")}
                                    onClick={() => document.getElementById("consentForm")?.click()} className="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center bg-gray-50 hover:bg-gray-100 transition-colors cursor-pointer">
                                    <div className="flex flex-col items-center">
                                        <input
                                            id={"consentForm"}
                                            type="file"
                                            accept=".pdf,.png,.jpg,.jpeg"
                                            className="hidden"
                                            onChange={(e) => handleFileSelect(e, "consentForm")}
                                        />

                                        {!formDataDoc.consentForm ? (
                                            <div className="flex flex-col items-center">
                                                <div className="w-12 h-12 bg-gray-200 rounded-lg flex items-center justify-center mb-3">
                                                    <span className="text-2xl text-gray-400">+</span>
                                                </div>
                                                <p className="text-sm text-gray-600">Click to upload or drag and drop</p>
                                                <p className="text-xs text-gray-500 mt-1">PDF, PNG, JPG up to 10MB</p>
                                            </div>
                                        ) : (
                                            <div className="flex flex-col items-center space-y-2">
                                                <div className="w-12 h-12 bg-green-100 rounded-lg flex items-center justify-center">
                                                    <span className="text-green-600 text-xl">✔</span>
                                                </div>
                                                <p className="text-sm text-gray-700">{formDataDoc.consentForm.name}</p>
                                                <p className="text-xs text-gray-500">{(formDataDoc.consentForm.size / 1024 / 1024).toFixed(2)} MB</p>
                                            </div>
                                        )}
                                    </div>
                                </div>
                            </div>

                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-2">
                                 Certificate of Registration Form *
                                </label>
                                <div onDragOver={handleDragOver}
                                    onDrop={(e) => handleDrop(e, "registrationForm")}
                                    onClick={() => document.getElementById("registrationForm")?.click()} className="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center bg-gray-50 hover:bg-gray-100 transition-colors cursor-pointer">
                                    <div className="flex flex-col items-center">
                                        <input
                                            id={"registrationForm"}
                                            type="file"
                                            accept=".pdf,.png,.jpg,.jpeg"
                                            className="hidden"
                                            onChange={(e) => handleFileSelect(e, "registrationForm")}
                                        />

                                        {!formDataDoc.registrationForm ? (
                                            <div className="flex flex-col items-center">
                                                <div className="w-12 h-12 bg-gray-200 rounded-lg flex items-center justify-center mb-3">
                                                    <span className="text-2xl text-gray-400">+</span>
                                                </div>
                                                <p className="text-sm text-gray-600">Click to upload or drag and drop</p>
                                                <p className="text-xs text-gray-500 mt-1">PDF, PNG, JPG up to 10MB</p>
                                            </div>
                                        ) : (
                                            <div className="flex flex-col items-center space-y-2">
                                                <div className="w-12 h-12 bg-green-100 rounded-lg flex items-center justify-center">
                                                    <span className="text-green-600 text-xl">✔</span>
                                                </div>
                                                <p className="text-sm text-gray-700">{formDataDoc.registrationForm.name}</p>
                                                <p className="text-xs text-gray-500">{(formDataDoc.registrationForm.size / 1024 / 1024).toFixed(2)} MB</p>
                                            </div>
                                        )}
                                    </div>
                                </div>
                            </div>

                            <div className="mt-6 pt-6 border-t border-gray-200">
                                <h3 className="text-lg font-semibold text-gray-800 mb-3">Confirmation</h3>
                                <p className="text-sm text-gray-600 mb-4">
                                    I, as the Team Leader, certify that all the information provided above is true and correct, and that all team members have given their consent to participate in the PUP-T Quiz Bee.
                                </p>

                                <label className="flex items-start cursor-pointer">
                                    <input
                                        type="checkbox"
                                        name="certification"
                                        checked={formData.certification}
                                        id='confirm'
                                        onChange={handleInputChange}
                                        className="mt-1 h-4 w-4 text-red-600 focus:ring-red-500 border-gray-300 rounded"
                                    />
                                    <span className="ml-3 text-sm text-gray-700">
                                        Yes, I confirm! *
                                    </span>
                                </label>
                            </div>
                        </div>
                    </div>
                );


            default:
                return null;
        }
    };
    const closeUploadModal = () => {
        setShowUploadModal(false);
        setSelectedMemberIndex(null);
    };

    const handleFileUpload = (e, fileType) => {
        const file = e.target.files[0];
        if (file && selectedMemberIndex !== null) {
            // Check file size (2MB = 2 * 1024 * 1024 bytes)
            const maxSize = 2 * 1024 * 1024; // 2MB
            if (file.size > maxSize) {
                Swal.fire({
                    icon: 'error',
                    title: 'File Too Large',
                    html: `
                        <div class="text-left">
                            <p class="mb-2">The file <strong>${file.name}</strong> exceeds the maximum size limit.</p>
                            <p class="text-sm text-gray-600">Maximum file size: <strong>2MB</strong></p>
                            <p class="text-sm text-gray-600">Your file size: <strong>${(file.size / 1024 / 1024).toFixed(2)}MB</strong></p>
                        </div>
                    `,
                    confirmButtonColor: '#f97316',
                    confirmButtonText: 'OK',
                    allowOutsideClick: false,
                });
                // Reset the input
                e.target.value = '';
                return;
            }
            const newMembers = [...formData.members];
            newMembers[selectedMemberIndex].requirements[fileType] = file;
            setFormData(prev => ({ ...prev, members: newMembers }));
            
            // Show success alert
            Swal.fire({
                icon: 'success',
                title: 'File Uploaded',
                text: `${file.name} has been uploaded successfully.`,
                timer: 2000,
                showConfirmButton: false,
                toast: true,
                position: 'top-end',
            });
        }
    };




    const removeFile = (fileType) => {
        if (selectedMemberIndex !== null) {
            Swal.fire({
                icon: 'question',
                title: 'Remove File?',
                text: 'Are you sure you want to remove this file?',
                showCancelButton: true,
                confirmButtonColor: '#f97316',
                cancelButtonColor: '#6b7280',
                confirmButtonText: 'Yes, Remove',
                cancelButtonText: 'Cancel',
            }).then((result) => {
                if (result.isConfirmed) {
                    const newMembers = [...formData.members];
                    newMembers[selectedMemberIndex].requirements[fileType] = null;
                    setFormData(prev => ({ ...prev, members: newMembers }));
                    
                    Swal.fire({
                        icon: 'success',
                        title: 'File Removed',
                        text: 'The file has been removed successfully.',
                        timer: 1500,
                        showConfirmButton: false,
                        toast: true,
                        position: 'top-end',
                    });
                }
            });
        }
    };

    const handleDropForMember = (
        e: DragEvent<HTMLDivElement>,
        memberIndex: number,
        field: keyof typeof formData.members[0]['requirements']
    ) => {
        e.preventDefault();
        const file = e.dataTransfer.files[0];
        if (!file) return;

        // Check file size (2MB = 2 * 1024 * 1024 bytes)
        const maxSize = 2 * 1024 * 1024; // 2MB
        if (file.size > maxSize) {
            Swal.fire({
                icon: 'error',
                title: 'File Too Large',
                html: `
                    <div class="text-left">
                        <p class="mb-2">The file <strong>${file.name}</strong> exceeds the maximum size limit.</p>
                        <p class="text-sm text-gray-600">Maximum file size: <strong>2MB</strong></p>
                        <p class="text-sm text-gray-600">Your file size: <strong>${(file.size / 1024 / 1024).toFixed(2)}MB</strong></p>
                    </div>
                `,
                confirmButtonColor: '#f97316',
                confirmButtonText: 'OK',
                allowOutsideClick: false,
            });
            return;
        }

        const newMembers = [...formData.members];
        newMembers[memberIndex].requirements[field] = file;
        setFormData(prev => ({ ...prev, members: newMembers }));
        
        // Show success alert
        Swal.fire({
            icon: 'success',
            title: 'File Uploaded',
            text: `${file.name} has been uploaded successfully.`,
            timer: 2000,
            showConfirmButton: false,
            toast: true,
            position: 'top-end',
        });
    };

    return (
        <>
            {
                currentStep !== 7 ? <div className="min-h-[50vh] max-h-[90vh] overflow-auto z-50 mt-10 w-full ">
                    <div className="max-w-4xl mx-auto ">
                        {/* Header */}
                        <div className="bg-gradient-to-r from-red-600 to-red-700 text-white p-6 rounded-t-2xl shadow-lg">
                            <div className="flex items-center justify-between mb-4">
                                <div className="flex items-center space-x-2">
                                    <div className="bg-white bg-opacity-20 p-2 rounded-lg">
                                        <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 20 20">
                                            <path d="M9 2a1 1 0 000 2h2a1 1 0 100-2H9z" />
                                            <path fillRule="evenodd" d="M4 5a2 2 0 012-2 3 3 0 003 3h2a3 3 0 003-3 2 2 0 012 2v11a2 2 0 01-2 2H6a2 2 0 01-2-2V5zm3 4a1 1 0 000 2h.01a1 1 0 100-2H7zm3 0a1 1 0 000 2h3a1 1 0 100-2h-3zm-3 4a1 1 0 100 2h.01a1 1 0 100-2H7zm3 0a1 1 0 100 2h3a1 1 0 100-2h-3z" clipRule="evenodd" />
                                        </svg>
                                    </div>

                                    <h1 className="text-2xl font-bold">{localStorage.getItem("event_name") || "Event Name"}</h1>
                                </div>
                            </div>
                        </div>

                        {/* Stepper */}

                        <div className="bg-white shadow-lg">
                            <div className="px-6 py-8">
                                <div className="flex items-center justify-between mb-8">
                                    {steps.map((step, index) => (
                                        <React.Fragment key={step.id}>
                                            <div className="flex flex-col items-center relative">
                                                <div
                                                    className={`w-10 h-10 rounded-full flex items-center justify-center font-semibold transition-all duration-300 ${index < currentStep
                                                        ? 'bg-red-600 text-white'
                                                        : index === currentStep
                                                            ? 'bg-red-600 text-white ring-4 ring-red-200'
                                                            : 'bg-gray-200 text-gray-500'
                                                        }`}
                                                >
                                                    {index < currentStep ? (
                                                        <Check className="w-5 h-5" />
                                                    ) : (
                                                        step.id
                                                    )}
                                                </div>
                                                <div className="text-center mt-2">
                                                    <div className={`text-sm font-medium ${index <= currentStep ? 'text-gray-900' : 'text-gray-400'}`}>
                                                        {step.title}
                                                    </div>
                                                    <div className={`text-xs ${index <= currentStep ? 'text-gray-500' : 'text-gray-400'}`}>
                                                        {step.description}
                                                    </div>
                                                </div>
                                            </div>
                                            {index < steps.length - 1 && (
                                                <div
                                                    className={`flex-1 h-1 mx-2 transition-all duration-300 ${index < currentStep ? 'bg-red-600' : 'bg-gray-200'
                                                        }`}
                                                    style={{ marginTop: '-40px' }}
                                                />
                                            )}
                                        </React.Fragment>
                                    ))}
                                </div>

                                {/* Content */}
                                <div className="mt-8 mb-8">
                                    {renderStepContent()}
                                </div>

                                {/* Navigation Buttons */}
                                <div className="flex justify-between items-center pt-6 border-t border-gray-200">
                                    <button
                                        onClick={prevStep}
                                        disabled={currentStep === 0}
                                        className={`flex items-center px-6 py-2.5 rounded-lg font-medium transition-all duration-200 ${currentStep === 0
                                            ? 'bg-gray-100 text-gray-400 cursor-not-allowed'
                                            : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
                                            }`}
                                    >
                                        <ChevronLeft className="w-4 h-4 mr-1" />
                                        Previous
                                    </button>

                                    <button
                                        onClick={() => {

                                            if (currentStep === steps.length - 1) {

                                                handleSubmit();
                                            }
                                            else if (currentStep == 2) {

                                                if (selectedSubjects.length == 0) return
                                                nextStep();
                                            }
                                            else if (currentStep == 0) {


                                                if (lobbyCode == null) return
                                                handleEnterCode();
                                                nextStep();
                                            }
                                            else if (currentStep == 3) {


                                                if (formData.fullName.trim() == "" || formData.email.trim() == ""
                                                    || formData.studentNumber.trim() == "" || formData.courseYear.trim() == "" || formData.contactNumber.trim() == ""
                                                ) return

                                                nextStep();
                                            }
                                            else {

                                                if (!agreePrivacy) return

                                                nextStep();
                                            }
                                        }}
                                        disabled={isSubmitting}
                                        className={`flex items-center px-6 py-2.5 rounded-lg font-medium transition-all duration-200 ${currentStep === steps.length - 1
                                            ? 'bg-green-600 text-white hover:bg-green-700'
                                            : 'bg-red-600 text-white hover:bg-red-700'
                                            }`}
                                    >
                                        {currentStep === steps.length - 1 && !isSubmitting ? 'Submit' : !isSubmitting ? 'Next' : ""}

                                        {isSubmitting && currentStep === steps.length - 1 ? (
                                            <>
                                                <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                                                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                                </svg>
                                                Submitting...
                                            </>
                                        ) : ''}
                                        {currentStep < steps.length - 1 && <ChevronRight className="w-4 h-4 ml-1" />}
                                    </button>
                                </div>
                            </div>
                        </div>


                        {/* Footer */}
                        <div className="bg-white rounded-b-2xl shadow-lg p-4 text-center text-sm text-gray-500">
                            Step {currentStep + 1} of {steps.length}
                        </div>

                        {/* Upload Requirements Modal */}
                        {showUploadModal && selectedMemberIndex !== null && (
                            <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
                                <div className="bg-white rounded-lg shadow-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto">
                                    <div className="sticky top-0 bg-white border-b border-gray-200 px-6 py-4 flex justify-between items-center">
                                        <h3 className="text-xl font-semibold text-gray-800">
                                            Upload Requirements - Member {selectedMemberIndex + 1}
                                        </h3>
                                        <button
                                            onClick={closeUploadModal}
                                            className="text-gray-400 hover:text-gray-600 transition-colors"
                                        >
                                            <X className="w-6 h-6" />
                                        </button>
                                    </div>

                                    <div className="px-6 py-4">
                                        <div className="bg-blue-50 border-l-4 border-blue-500 p-4 rounded mb-6">
                                            <p className="text-sm text-gray-700 font-medium mb-2">Required Documents:</p>
                                            <ul className="text-sm text-gray-700 list-disc list-inside space-y-1">
                                                <li>Valid Student's ID</li>
                                                <li>Registration Form</li>
                                                <li>Signed Consent Form</li>
                                            </ul>
                                        </div>

                                        <div className="space-y-6">
                                            {/* Student ID Upload */}
                                            <div>
                                                <label className="block text-sm font-medium text-gray-700 mb-2">
                                                    Valid Student's ID *
                                                </label>
                                                {formData.members[selectedMemberIndex].requirements.studentId ? (
                                                    <div className="border border-gray-300 rounded-lg p-4 bg-green-50">
                                                        <div className="flex items-center justify-between">
                                                            <div className="flex items-center gap-2">
                                                                <Check className="w-5 h-5 text-green-600" />
                                                                <span className="text-sm text-gray-700">
                                                                    {formData.members[selectedMemberIndex].requirements.studentId.name}
                                                                </span>
                                                            </div>
                                                            <button
                                                                onClick={() => removeFile('studentId')}
                                                                className="text-red-600 hover:text-red-800 text-sm"
                                                            >
                                                                Remove
                                                            </button>
                                                        </div>
                                                    </div>
                                                ) : (
                                                    <div onDrop={(e) => handleDropForMember(e, selectedMemberIndex, "studentId")}
                                                        onDragOver={(e) => e.preventDefault()} className="border-2 border-dashed border-gray-300 rounded-lg p-6 text-center bg-gray-50 hover:bg-gray-100 transition-colors">
                                                        <label className="cursor-pointer">
                                                            <div className="flex flex-col items-center">
                                                                <div className="w-12 h-12 bg-gray-200 rounded-lg flex items-center justify-center mb-3">
                                                                    <Upload className="w-6 h-6 text-gray-400" />
                                                                </div>
                                                                <p className="text-sm text-gray-600">Click to upload or drag and drop</p>
                                                                <p className="text-xs text-gray-500 mt-1">PDF, PNG, JPG up to 2MB</p>
                                                            </div>
                                                            <input
                                                                type="file"
                                                                className="hidden"
                                                                accept=".pdf,.png,.jpg,.jpeg"
                                                                onChange={(e) => handleFileUpload(e, 'studentId')}
                                                            />
                                                        </label>
                                                    </div>
                                                )}
                                            </div>

                                            {/* Registration Form Upload */}
                                            <div>
                                                <label className="block text-sm font-medium text-gray-700 mb-2">
                                                  Certificate of Registration Form *
                                                </label>
                                                {formData.members[selectedMemberIndex].requirements.registrationForm ? (
                                                    <div className="border border-gray-300 rounded-lg p-4 bg-green-50">
                                                        <div className="flex items-center justify-between">
                                                            <div className="flex items-center gap-2">
                                                                <Check className="w-5 h-5 text-green-600" />
                                                                <span className="text-sm text-gray-700">
                                                                    {formData.members[selectedMemberIndex].requirements.registrationForm.name}
                                                                </span>
                                                            </div>
                                                            <button
                                                                onClick={() => removeFile('registrationForm')}
                                                                className="text-red-600 hover:text-red-800 text-sm"
                                                            >
                                                                Remove
                                                            </button>
                                                        </div>
                                                    </div>
                                                ) : (
                                                    <div onDrop={(e) => handleDropForMember(e, selectedMemberIndex, "registrationForm")}
                                                        onDragOver={(e) => e.preventDefault()} className="border-2 border-dashed border-gray-300 rounded-lg p-6 text-center bg-gray-50 hover:bg-gray-100 transition-colors">
                                                        <label className="cursor-pointer">
                                                            <div className="flex flex-col items-center">
                                                                <div className="w-12 h-12 bg-gray-200 rounded-lg flex items-center justify-center mb-3">
                                                                    <Upload className="w-6 h-6 text-gray-400" />
                                                                </div>
                                                                <p className="text-sm text-gray-600">Click to upload or drag and drop</p>
                                                                <p className="text-xs text-gray-500 mt-1">PDF, PNG, JPG up to 2MB</p>
                                                            </div>
                                                            <input
                                                                type="file"
                                                                className="hidden"
                                                                accept=".pdf,.png,.jpg,.jpeg"
                                                                onChange={(e) => handleFileUpload(e, 'registrationForm')}
                                                            />
                                                        </label>
                                                    </div>
                                                )}
                                            </div>

                                            {/* Consent Form Upload */}
                                            <div>
                                                <label className="block text-sm font-medium text-gray-700 mb-2">
                                                    Signed Consent Form *
                                                </label>
                                                {formData.members[selectedMemberIndex].requirements.consentForm ? (
                                                    <div className="border border-gray-300 rounded-lg p-4 bg-green-50">
                                                        <div className="flex items-center justify-between">
                                                            <div className="flex items-center gap-2">
                                                                <Check className="w-5 h-5 text-green-600" />
                                                                <span className="text-sm text-gray-700">
                                                                    {formData.members[selectedMemberIndex].requirements.consentForm.name}
                                                                </span>
                                                            </div>
                                                            <button
                                                                onClick={() => removeFile('consentForm')}
                                                                className="text-red-600 hover:text-red-800 text-sm"
                                                            >
                                                                Remove
                                                            </button>
                                                        </div>
                                                    </div>
                                                ) : (
                                                    <div onDrop={(e) => handleDropForMember(e, selectedMemberIndex, "consentForm")}
                                                        onDragOver={(e) => e.preventDefault()} className="border-2 border-dashed border-gray-300 rounded-lg p-6 text-center bg-gray-50 hover:bg-gray-100 transition-colors">
                                                        <label className="cursor-pointer">
                                                            <div className="flex flex-col items-center">
                                                                <div className="w-12 h-12 bg-gray-200 rounded-lg flex items-center justify-center mb-3">
                                                                    <Upload className="w-6 h-6 text-gray-400" />
                                                                </div>
                                                                <p className="text-sm text-gray-600">Click to upload or drag and drop</p>
                                                                <p className="text-xs text-gray-500 mt-1">PDF, PNG, JPG up to 2MB</p>
                                                            </div>
                                                            <input
                                                                type="file"
                                                                className="hidden"
                                                                accept=".pdf,.png,.jpg,.jpeg"
                                                                onChange={(e) => handleFileUpload(e, 'consentForm')}
                                                            />
                                                        </label>
                                                    </div>
                                                )}
                                            </div>
                                        </div>
                                    </div>

                                    <div className="sticky bottom-0 bg-gray-50 border-t border-gray-200 px-6 py-4 flex justify-end">
                                        <button
                                            onClick={closeUploadModal}
                                            className="px-6 py-2.5 bg-red-600 hover:bg-red-700 text-white rounded-lg font-medium transition-colors"
                                        >
                                            Done
                                        </button>
                                    </div>
                                </div>
                            </div>
                        )}


                        {/* Upload Requirements Modal */}
                        {showUploadModalTeamLeader && (
                            <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
                                <div className="bg-white rounded-lg shadow-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto">
                                    <div className="sticky top-0 bg-white border-b border-gray-200 px-6 py-4 flex justify-between items-center">
                                        <h3 className="text-xl font-semibold text-gray-800">
                                            Upload Requirements - Team Leader
                                        </h3>
                                        <button
                                            onClick={() => setShowUploadModalTeamLeader(false)}
                                            className="text-gray-400 hover:text-gray-600 transition-colors"
                                        >
                                            <X className="w-6 h-6" />
                                        </button>
                                    </div>

                                    <div className="px-6 py-4">
                                        <div className="bg-blue-50 border-l-4 border-blue-500 p-4 rounded mb-6">
                                            <p className="text-sm text-gray-700 font-medium mb-2">Required Documents:</p>
                                            <ul className="text-sm text-gray-700 list-disc list-inside space-y-1">
                                                <li>Valid Student's ID</li>
                                                <li>Registration Form</li>
                                                <li>Signed Consent Form</li>
                                            </ul>
                                        </div>

                                        <div className="space-y-6">
                                            {/* Student ID Upload */}
                                            <div>
                                                <label className="block text-sm font-medium text-gray-700 mb-2">
                                                    Valid Student's ID *
                                                </label>
                                                {formDataDoc.studentId ? (
                                                    <div className="border border-gray-300 rounded-lg p-4 bg-green-50 flex justify-between">
                                                        <div className="flex items-center justify-between">
                                                            <div className="flex items-center gap-2">
                                                                <Check className="w-5 h-5 text-green-600" />
                                                                <span className="text-sm text-gray-700">
                                                                    {formDataDoc.studentId.name}
                                                                </span>
                                                            </div>

                                                        </div>
                                                        <button
                                                            onClick={() => {
                                                                Swal.fire({
                                                                    icon: 'question',
                                                                    title: 'Remove File?',
                                                                    text: 'Are you sure you want to remove this file?',
                                                                    showCancelButton: true,
                                                                    confirmButtonColor: '#f97316',
                                                                    cancelButtonColor: '#6b7280',
                                                                    confirmButtonText: 'Yes, Remove',
                                                                    cancelButtonText: 'Cancel',
                                                                }).then((result) => {
                                                                    if (result.isConfirmed) {
                                                                        setFormDataDoc(prev => ({
                                                                            ...prev,
                                                                            studentId: null
                                                                        }));
                                                                        Swal.fire({
                                                                            icon: 'success',
                                                                            title: 'File Removed',
                                                                            text: 'The file has been removed successfully.',
                                                                            timer: 1500,
                                                                            showConfirmButton: false,
                                                                            toast: true,
                                                                            position: 'top-end',
                                                                        });
                                                                    }
                                                                });
                                                            }}
                                                            className="text-red-600 hover:text-red-800 text-sm"
                                                        >
                                                            Remove
                                                        </button>
                                                    </div>
                                                ) : (
                                                    <div onDragOver={handleDragOver}
                                                        onDrop={(e) => handleDrop(e, "studentId")} className="border-2 border-dashed border-gray-300 rounded-lg p-6 text-center bg-gray-50 hover:bg-gray-100 transition-colors">
                                                        <label className="cursor-pointer">
                                                            <div className="flex flex-col items-center">
                                                                <div className="w-12 h-12 bg-gray-200 rounded-lg flex items-center justify-center mb-3">
                                                                    <Upload className="w-6 h-6 text-gray-400" />
                                                                </div>
                                                                <p className="text-sm text-gray-600">Click to upload or drag and drop</p>
                                                                <p className="text-xs text-gray-500 mt-1">PDF, PNG, JPG up to 2MB</p>
                                                            </div>
                                                            <input
                                                                type="file"
                                                                className="hidden"
                                                                accept=".pdf,.png,.jpg,.jpeg"
                                                                onChange={(e) => handleFileSelect(e, 'studentId')}
                                                            />
                                                        </label>
                                                    </div>
                                                )}
                                            </div>

                                            {/* Registration Form Upload */}
                                            <div>
                                                <label className="block text-sm font-medium text-gray-700 mb-2">
                                                    Certificate of Registration Form *
                                                </label>
                                                {formDataDoc.registrationForm ? (
                                                    <div className="border border-gray-300 rounded-lg p-4 bg-green-50 flex justify-between">
                                                        <div className="flex items-center justify-between">
                                                            <div className="flex items-center gap-2">
                                                                <Check className="w-5 h-5 text-green-600" />
                                                                <span className="text-sm text-gray-700">
                                                                    {formDataDoc.registrationForm.name}
                                                                </span>
                                                            </div>

                                                        </div>
                                                        <button
                                                            onClick={() => {
                                                                Swal.fire({
                                                                    icon: 'question',
                                                                    title: 'Remove File?',
                                                                    text: 'Are you sure you want to remove this file?',
                                                                    showCancelButton: true,
                                                                    confirmButtonColor: '#f97316',
                                                                    cancelButtonColor: '#6b7280',
                                                                    confirmButtonText: 'Yes, Remove',
                                                                    cancelButtonText: 'Cancel',
                                                                }).then((result) => {
                                                                    if (result.isConfirmed) {
                                                                        setFormDataDoc(prev => ({
                                                                            ...prev,
                                                                            registrationForm: null
                                                                        }));
                                                                        Swal.fire({
                                                                            icon: 'success',
                                                                            title: 'File Removed',
                                                                            text: 'The file has been removed successfully.',
                                                                            timer: 1500,
                                                                            showConfirmButton: false,
                                                                            toast: true,
                                                                            position: 'top-end',
                                                                        });
                                                                    }
                                                                });
                                                            }}
                                                            className="text-red-600 hover:text-red-800 text-sm"
                                                        >
                                                            Remove
                                                        </button>
                                                    </div>
                                                ) : (
                                                    <div onDragOver={handleDragOver}
                                                        onDrop={(e) => handleDrop(e, "registrationForm")} className="border-2 border-dashed border-gray-300 rounded-lg p-6 text-center bg-gray-50 hover:bg-gray-100 transition-colors">
                                                        <label className="cursor-pointer">
                                                            <div className="flex flex-col items-center">
                                                                <div className="w-12 h-12 bg-gray-200 rounded-lg flex items-center justify-center mb-3">
                                                                    <Upload className="w-6 h-6 text-gray-400" />
                                                                </div>
                                                                <p className="text-sm text-gray-600">Click to upload or drag and drop</p>
                                                                <p className="text-xs text-gray-500 mt-1">PDF, PNG, JPG up to 2MB</p>
                                                            </div>
                                                            <input
                                                                type="file"
                                                                className="hidden"
                                                                accept=".pdf,.png,.jpg,.jpeg"
                                                                onChange={(e) => handleFileSelect(e, 'registrationForm')}
                                                            />
                                                        </label>
                                                    </div>
                                                )}
                                            </div>

                                            {/* Consent Form Upload */}
                                            <div>
                                                <label className="block text-sm font-medium text-gray-700 mb-2">
                                                    Signed Consent Form *
                                                </label>
                                                {formDataDoc.consentForm ? (
                                                    <div className="border border-gray-300 rounded-lg p-4 bg-green-50 flex justify-between">
                                                        <div className="flex items-center justify-between">
                                                            <div className="flex items-center gap-2">
                                                                <Check className="w-5 h-5 text-green-600" />
                                                                <span className="text-sm text-gray-700">
                                                                    {formDataDoc.consentForm.name}
                                                                </span>
                                                            </div>

                                                        </div>
                                                        <button
                                                            onClick={() => {
                                                                Swal.fire({
                                                                    icon: 'question',
                                                                    title: 'Remove File?',
                                                                    text: 'Are you sure you want to remove this file?',
                                                                    showCancelButton: true,
                                                                    confirmButtonColor: '#f97316',
                                                                    cancelButtonColor: '#6b7280',
                                                                    confirmButtonText: 'Yes, Remove',
                                                                    cancelButtonText: 'Cancel',
                                                                }).then((result) => {
                                                                    if (result.isConfirmed) {
                                                                        setFormDataDoc(prev => ({
                                                                            ...prev,
                                                                            consentForm: null
                                                                        }));
                                                                        Swal.fire({
                                                                            icon: 'success',
                                                                            title: 'File Removed',
                                                                            text: 'The file has been removed successfully.',
                                                                            timer: 1500,
                                                                            showConfirmButton: false,
                                                                            toast: true,
                                                                            position: 'top-end',
                                                                        });
                                                                    }
                                                                });
                                                            }}
                                                            className="text-red-600 hover:text-red-800 text-sm"
                                                        >
                                                            Remove
                                                        </button>
                                                    </div>
                                                ) : (
                                                    <div onDragOver={handleDragOver}
                                                        onDrop={(e) => handleDrop(e, "consentForm")} className="border-2 border-dashed border-gray-300 rounded-lg p-6 text-center bg-gray-50 hover:bg-gray-100 transition-colors">
                                                        <label className="cursor-pointer">
                                                            <div className="flex flex-col items-center">
                                                                <div className="w-12 h-12 bg-gray-200 rounded-lg flex items-center justify-center mb-3">
                                                                    <Upload className="w-6 h-6 text-gray-400" />
                                                                </div>
                                                                <p className="text-sm text-gray-600">Click to upload or drag and drop</p>
                                                                <p className="text-xs text-gray-500 mt-1">PDF, PNG, JPG up to 2MB</p>
                                                            </div>
                                                            <input
                                                                type="file"
                                                                className="hidden"
                                                                accept=".pdf,.png,.jpg,.jpeg"
                                                                onChange={(e) => handleFileSelect(e, 'consentForm')}
                                                            />
                                                        </label>
                                                    </div>
                                                )}
                                            </div>
                                        </div>
                                    </div>

                                    <div className="sticky bottom-0 bg-gray-50 border-t border-gray-200 px-6 py-4 flex justify-end">
                                        <button
                                            onClick={() => setShowUploadModalTeamLeader(false)}
                                            className="px-6 py-2.5 bg-red-600 hover:bg-red-700 text-white rounded-lg font-medium transition-colors"
                                        >
                                            Done
                                        </button>
                                    </div>
                                </div>
                            </div>
                        )}
                    </div>
                </div> : <div className="w-[50rem] m-auto">
                    {/* Animated background elements */}
                    <div className="absolute inset-0 overflow-hidden">
                        <div className="absolute -top-40 -right-40 w-80 h-80 bg-white/10 rounded-full blur-3xl animate-pulse"></div>
                        <div className="absolute -bottom-40 -left-40 w-80 h-80 bg-white/5 rounded-full blur-3xl animate-pulse delay-1000"></div>
                    </div>


                    <div className={`relative z-10 transform transition-all duration-1000 ${isVisible ? 'translate-y-0 opacity-100 scale-100' : 'translate-y-8 opacity-0 scale-95'
                        }`}>
                        <div className="bg-white/95 backdrop-blur-xl rounded-3xl p-8 md:p-12 w-full shadow-2xl border border-white/20">

                            {/* Success Icon */}
                            <div className="relative mb-8">
                                <div className="mx-auto w-20 h-20 bg-gradient-to-br from-green-400 to-green-600 rounded-full flex items-center justify-center shadow-lg">
                                    <CheckCircle className="w-12 h-12 text-white" />
                                </div>
                                <div className="absolute -top-2 -right-2">
                                    <Sparkles className="w-8 h-8 text-yellow-400 animate-spin" style={{ animationDuration: '3s' }} />
                                </div>
                            </div>

                            {/* Main Message */}
                            <div className="text-center mb-8">
                                <h1 className="text-3xl font-bold text-gray-800 mb-3">
                                    Successfully Registered!
                                </h1>
                                <p className="text-gray-600 leading-relaxed">
                                    You're all set for the event. We're excited to have you join us!
                                </p>
                            </div>

                            {/* Event Details Cards */}
                            <div className="space-y-4 mb-8">
                                {/* Event Date Card */}
                                {/* <div className="bg-red-50 border border-red-100 rounded-2xl p-4 flex items-center space-x-6 hover:bg-red-100 transition-colors duration-300">
                                            <div className="w-12 h-12 bg-red-600 rounded-full flex items-center justify-center">
                                                <Calendar className="w-6 h-6 text-white" />
                                            </div>
                                            <div className="flex flex-col justify-start">
                                                <h3 className="font-semibold text-gray-800 text-start">Event Date</h3>
                                                <p className="text-sm text-gray-600">{eventDate.toLocaleDateString('en-US', {
                                                    weekday: 'long',
                                                    year: 'numeric',
                                                    month: 'long',
                                                    day: 'numeric'
                                                })}</p>
                                            </div>
                                        </div> */}

                                {/* Invite Link Card */}
                                {/* <div className="bg-blue-50 border border-blue-100 rounded-2xl p-4 flex items-center space-x-6 hover:bg-blue-100 transition-colors duration-300">
                                            <div className="w-12 h-12 bg-blue-600 rounded-full flex items-center justify-center">
                                                <Mail className="w-6 h-6 text-white" />
                                            </div>
                                            <div className="flex flex-col justify-start">
                                                <h3 className="font-semibold text-gray-800 text-start">Invite Link</h3>
                                                <p className="text-sm text-gray-600">
                                                    Expect your invite link on {inviteDate.toLocaleDateString('en-US', {
                                                        month: 'short',
                                                        day: 'numeric'
                                                    })}
                                                </p>
                                            </div>
                                        </div> */}
                            </div>

                            {/* Call to Action */}
                            <div className="text-center space-y-4">
                                {/* <div className="bg-gradient-to-r from-red-600 to-red-700 text-white px-6 py-3 rounded-xl font-medium shadow-lg hover:shadow-xl transform hover:-translate-y-0.5 transition-all duration-300 cursor-pointer flex items-center justify-center space-x-2">
                                            <span>Add to Calendar</span>
                                            <ArrowRight className="w-4 h-4" />
                                        </div> */}

                                <p className="text-xs text-gray-500">
                                    Keep an eye on your email for updates and your event invite link
                                </p>
                            </div>

                            {/* Decorative bottom border */}
                            <div className="mt-8 h-1 bg-gradient-to-r from-red-400 via-red-600 to-red-400 rounded-full"></div>
                        </div>
                    </div>
                </div>
            }


        </>

    );
}