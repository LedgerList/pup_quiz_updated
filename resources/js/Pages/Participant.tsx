import Footer from "@/CustomComponents/Footer";
import PreRegistrationForm from "@/CustomComponents/PreRegistrationForm";
import { router } from "@inertiajs/react";
import axios from "axios";
import { ArrowRight, Calendar, CheckCircle, Mail, Sparkles, Trash2, Trash2Icon } from "lucide-react";
import React, { useState, useEffect } from "react";
import Swal from 'sweetalert2';

type Props = {};

const JoinPage = (props: Props) => {
    const [joinCode, setJoinCode] = useState("");
    const [isJoining, setIsJoining] = useState(false);
    const [csrfToken, setCsrfToken] = useState<string | null>(null);
    const [showLoginPrompt, setShowLoginPrompt] = useState(false);
    const [teamName, setTeamName] = useState("");
    const [members, setMembers] = useState([{ name: "" }]);
    const [currentStep, setCurrentStep] = useState(1);
    const [selectedSubjects, setSelectedSubjects] = useState<string[]>([]);
    const [lobbyCode, setLobbyCode] = useState(null)
    const [subjects, setSubjects] = useState([]);
    const [participantId, setParticipantId] = useState(null);
    // Pre-registration form states
    // Pre-registration form states
    const [formData, setFormData] = useState({
        teamName: '',
        teamLeader: '',
        teamLeaderEmail: ''
    });
    const [isSubmitting, setIsSubmitting] = useState(false);


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

    const handleJoin = async () => {
        setIsJoining(true); // Disable button immediately
        setShowLoginPrompt(false); // Hide prompt at the start of a new attempt

        if (!joinCode.trim()) {
            Swal.fire({
                toast: true,
                position: 'top-end',
                icon: 'error',
                title: 'Please enter a join code.',
                showConfirmButton: false,
                timer: 3000,
                timerProgressBar: true,
            });
            setIsJoining(false);
            return;
        }

        try {
            const { data } = await axios.post('/quizzes/join', { code: joinCode });

            Swal.fire({
                toast: true,
                position: 'top-end',
                icon: 'success',
                title: data.message || 'Successfully joined the quiz!',
                showConfirmButton: false,
                timer: 3000,
                timerProgressBar: true,
            });
            setJoinCode(''); // Clear the input field
            setShowLoginPrompt(false); // Hide the prompt on success

            if (data.quiz_id) {
                window.location.href = `/quizzes/${data.quiz_id}/starting`;
            } else {
                console.warn("Joined quiz, but no quiz_id for redirection.");
            }
        } catch (error: any) {
            console.error("Error joining quiz:", error);
            const status = error?.response?.status;

            if (status === 401 || status === 419) {
                setShowLoginPrompt(true);
            }

            let errorMessage = error?.response?.data?.message || 'Quiz not found or failed to join.';
            if (status === 422 && error.response?.data?.errors) {
                const validationErrors = Object.values(error.response.data.errors).flat();
                errorMessage = validationErrors.join(' ') || errorMessage;
            } else if (status === 403) {
                errorMessage = 'You do not have permission to join this quiz.';
            } else if (status === 419) {
                errorMessage = 'Your session has expired. Please log in to join the quiz.';
            }

            Swal.fire({
                toast: true,
                position: 'top-end',
                icon: 'error',
                title: errorMessage,
                showConfirmButton: false,
                timer: 3000,
                timerProgressBar: true,
            });
        } finally {
            setIsJoining(false); // Re-enable button
        }
    };

    const handlePreRegistration = async () => {

  
        if (!csrfToken) {
            console.error('CSRF token not found');
            return;
        }

        setIsJoining(true);
        setIsSubmitting(true);
        try {
            const response = await fetch('/participant', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': csrfToken,
                },
                body: JSON.stringify({
                    "team": formData.teamName,
                    "team_leader": formData.teamLeader,
                    "team_leader_email": formData.teamLeaderEmail,
                    "subject": selectedSubjects[0],
                    members: JSON.stringify(members),
                    "lobbyCode": lobbyCode
                }),
            });

            const data = await response.json();

            if (response.ok) {
                setParticipantId(data.user.id)
                setCurrentStep(3);
            } else if (response.status === 401) {
                setShowLoginPrompt(true);
            } else if (data.error === 'Team name already exists') {
                Swal.fire({
                    icon: 'error',
                    title: 'Team Name Already Exists',
                    text: 'Please choose a different team name.',
                    confirmButtonColor: '#f97316',
                });
            } else {
                throw new Error(data.error || 'Failed to create team');
            }
        } catch (error) {
            console.error('Error:', error);
            Swal.fire({
                icon: 'error',
                title: 'Error',
                text: 'An error occurred while creating the team. Please try again.',
                confirmButtonColor: '#f97316',
            });
        } finally {
            setIsJoining(false);
            setIsSubmitting(false);
        }
    };

    const verifyTeam = async (teamNameToVerify: string) => {
        if (!csrfToken) {
            console.error('CSRF token not found');
            return;
        }

        try {
            const response = await fetch('/participant/verify-team', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': csrfToken, // If CSRF is required
                },
                body: JSON.stringify({ team_name: teamNameToVerify })
            });

            const data = await response.json();

            if (data.exists) {

                await axios.get(`/participant-code-update/${data.id}/${lobbyCode}`)
                setParticipantId(data.id)
                setTeamName(teamNameToVerify);
                setCurrentStep(3);
                Swal.fire({
                    icon: 'success',
                    title: 'Team Found!',
                    text: 'Please proceed with subject selection.',
                    confirmButtonColor: '#f97316',
                });
                // router.get(`lobby/${data.id}`)
            } else if (response.status === 401) {
                setShowLoginPrompt(true);
            } else {
                Swal.fire({
                    icon: 'error',
                    title: 'Team Not Found',
                    text: 'Please check the team name or create a new team.',
                    confirmButtonColor: '#f97316',
                });
            }
        } catch (error) {
            console.error('Error:', error);
            Swal.fire({
                icon: 'error',
                title: 'Error',
                text: 'An error occurred while verifying the team. Please try again.',
                confirmButtonColor: '#f97316',
            });
        }
    };

    const toggleSubject = (subject: string) => {
        setSelectedSubjects(prev =>
            prev.includes(subject)
                ? prev.filter(s => s !== subject)
                : [...prev, subject]
        );
    };

    const handleSubjectSelection = async () => {
        const filteredSubject = subjects.filter(subject => selectedSubjects.includes(subject.subject_name))

        if (filteredSubject.length < 1) {
            Swal.fire({
                icon: 'warning',
                title: 'No Subjects Selected',
                text: 'Please select at least one subject to continue.',
                confirmButtonColor: '#f97316',
            });
            return;
        }

        router.get(`/lobby/${subjects[0]['lobby_id']}/${filteredSubject[0].id}/${participantId}`)

        //  alert((`/lobby/${subjects[0]['lobby_id']}/${filteredSubject[0].id}`))


    };

    const handleEnterCode = async () => {
        try {
            const response = await axios.get(`/check-lobby-code/${lobbyCode}`)

            setSubjects(response.data)
            setCurrentStep(2)
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
    const handleFormChange = (field, value) => {
        setFormData(prev => ({
            ...prev,
            [field]: value
        }));
    };

      const [isVisible, setIsVisible] = useState(false);
  const [showConfetti, setShowConfetti] = useState(false);

  useEffect(() => {
    setIsVisible(true);
    setTimeout(() => setShowConfetti(true), 500);
  }, []);

  const eventDate = new Date();
  eventDate.setDate(eventDate.getDate() + 14); // 14 days from now
  const inviteDate = new Date();
  inviteDate.setDate(inviteDate.getDate() + 9); // 5 days before event
    return (
        <div
            className="min-h-screen w-full bg-cover bg-center  flex items-start justify-center relative"
            style={{
                backgroundImage: "url('/images/bgonly.png')",
            }}
        >
            <div className="">
           

                {/* {showLoginPrompt && (
                    <p className="mt-4 text-center text-red-700 text-lg font-semibold">
                        Please <a href="/login" className="underline hover:text-red-900">Login</a> to join.
                    </p>
                )} */}
            </div>
                    <PreRegistrationForm />
            <Footer />

            <div className="absolute bottom-0 left-0 right-0">
                <img
                    src="/images/icons/footer.png"
                    alt="Footer"
                    className="w-full"
                />
            </div>
        </div>
    );
};

export default JoinPage;