import React, { useState, useEffect } from 'react';
import { Search, User, Clock, MapPin, Calendar, Filter, BanIcon, UserRoundCheckIcon, Hash, LayoutDashboardIcon, Eye, ChevronLeft } from 'lucide-react';
import AuthenticatedLayout from '@/Layouts/AuthenticatedLayout';
import { router, usePage } from '@inertiajs/react';
import { PageProps } from '@/types';
import Swal from 'sweetalert2';
import { Button } from '@/Components/ui/button';
type Props = {}

const PreRegistrationLogs = (props: Props) => {
    const { logs, lobbies } = usePage().props
    const { auth } = usePage<PageProps>().props
    const [searchTerm, setSearchTerm] = useState('');
    const [filterActive, setFilterActive] = useState('all');
    const [selectedLobby, setSelectedLobby] = useState<number | null>(null);
    const [lobbySearchTerm, setLobbySearchTerm] = useState('');
    const [availableLobbies, setAvailableLobbies] = useState<any[]>([]);

    useEffect(() => {
        if (lobbies && lobbies.length > 0) {
            setAvailableLobbies(lobbies);
            if (!selectedLobby && lobbies[0]) {
                setSelectedLobby(lobbies[0].id);
            }
        }
    }, [lobbies]);

    const filteredLobbies = availableLobbies.filter(lobby =>
        lobby.name.toLowerCase().includes(lobbySearchTerm.toLowerCase())
    );

    const sessionData = logs
    const formatDateTime = (timestamp) => {
        if (!timestamp) return 'Active Session';
        const date = new Date(timestamp);
        return date.toLocaleString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
    };

    const calculateDuration = (created, logout) => {
        if (!logout) return 'Active';
        const start = new Date(created);
        const end = new Date(logout);
        const diff = Math.abs(end - start);
        const minutes = Math.floor(diff / 60000);
        const seconds = Math.floor((diff % 60000) / 1000);
        return `${minutes}m ${seconds}s`;
    };

    const getStatusBadge = (logoutTime) => {
        if (!logoutTime) {
            return (
                <span className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-green-100 text-green-800 border border-green-200">
                    <div className="w-2 h-2 bg-green-400 rounded-full mr-2 animate-pulse"></div>
                    Active
                </span>
            );
        }
        return (
            <span className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-gray-100 text-gray-800 border border-gray-200">
                <div className="w-2 h-2 bg-gray-400 rounded-full mr-2"></div>
                Ended
            </span>
        );
    };

    const filteredData = sessionData.filter(session => {
        // Filter by selected lobby if one is selected
        if (selectedLobby) {
            if (session.lobby_id !== selectedLobby) {
                return false;
            }
        }

        const matchesSearch = session.participant?.team?.trim().toLowerCase().includes(searchTerm.trim().toLowerCase()) ||
            session.participant?.team_leader?.trim().toLowerCase().includes(searchTerm.trim().toLowerCase())

        if (filterActive === 'all') return matchesSearch;
        if (filterActive === 'active') return matchesSearch && session.status === 2;
        if (filterActive === 'ended') return matchesSearch && session.status === 1;

        return matchesSearch;
    });
    function convertToPhilippineTime(utcDateString: string): string {
        const date = new Date(utcDateString);
        return date.toLocaleString("en-PH", {
            timeZone: "Asia/Manila",
            year: "numeric",
            month: "2-digit",
            day: "2-digit",
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
            hour12: false, // set to true if you want AM/PM
        });
    }
    // Function to handle viewing files
    const handleViewFiles = (files) => {
        // files should be an array of file objects with properties: url, type, name
        // Example: [{ url: 'path/to/file.pdf', type: 'pdf', name: 'document.pdf' }]

        if (!files || files.length === 0) {
            Swal.fire({
                icon: 'info',
                title: 'No Files',
                text: 'No files available to view',
                confirmButtonColor: '#16a34a'
            });
            return;
        }// group files by person name in parentheses, e.g. "(John)"
        const grouped = files.reduce((acc, file) => {
            const match = file.name.match(/\((.*?)\)/); // extract text inside parentheses
            const personName = match ? match[1] : 'Unknown'; // default fallback

            if (!acc[personName]) acc[personName] = [];
            acc[personName].push(file);
            return acc;
        }, {});

        // Generate HTML content for multiple files
        const filesHTML = Object.entries(grouped).map(([personName, personFiles]) => {
            const fileCards = personFiles.map((file, index) => {
                if (file.type === 'pdf' || file.url.toLowerCase().endsWith('.pdf')) {
                    return `
            <div class="w-1/3 p-2 text-center">
              <h4 class="font-semibold text-gray-700 mb-2">${file.name.replace(/\s*\(.*?\)\s*/, '')}</h4>
              <iframe 
                src="${file.url}" 
                width="100%" 
                height="300px" 
                style="border: 1px solid #ddd; border-radius: 8px;"
              ></iframe>
              <a href="${file.url}" target="_blank" class="inline-block mt-2 px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700 transition">
                Open in New Tab
              </a>
            </div>
          `;
                } else if (file.type === 'image' || /\.(jpg|jpeg|png|gif|webp|svg)$/i.test(file.url)) {
                    return `
            <div class="w-1/3 p-2 text-center">
              <h4 class="font-semibold text-gray-700 mb-2">${file.name.replace(/\s*\(.*?\)\s*/, '')}</h4>
              <img 
                src="${file.url}" 
                alt="${file.name}" 
                style="max-width: 100%; height: auto; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);"
              />
              <a href="${file.url}" target="_blank" class="inline-block mt-2 px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700 transition">
                View Full Size
              </a>
            </div>
          `;
                } else {
                    return `
            <div class="w-1/3 p-2 text-center">
              <h4 class="font-semibold text-gray-700 mb-2">${file.name.replace(/\s*\(.*?\)\s*/, '')}</h4>
              <p class="text-gray-600 mb-2">File type not supported for preview</p>
              <a href="${file.url}" target="_blank" class="inline-block px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700 transition">
                Download File
              </a>
            </div>
          `;
                }
            }).join('');

            return `
        <div class="mb-8 pb-4 border-b">
          <h3 class="text-xl font-bold text-gray-800 mb-4">${personName}</h3>
          <div class="flex flex-wrap -m-2">
            ${fileCards}
          </div>
        </div>
      `;
        }).join('');
        Swal.fire({
            title: 'View Files',
            html: `
                <div style="max-height: 600px; overflow-y: auto; text-align: left;">
                    ${filesHTML}
                </div>
            `,
            width: '80%',
            showCloseButton: true,
            showConfirmButton: false,
            customClass: {
                popup: 'swal-wide',
                htmlContainer: 'swal-html-container'
            }
        });
    };
    return (
        <AuthenticatedLayout>
            <div className="min-h-screen bg-gradient-to-br from-red-50 via-amber-50 to-yellow-50 p-6">
                <div className="max-w-7xl mx-auto">
                    {/* Header */}
                    <div className='flex justify-between items-center'>
                        <div className="mb-8">
                            <h1 className="text-4xl font-bold text-gray-900 mb-2 bg-gradient-to-r from-red-600 to-amber-600 bg-clip-text text-transparent">
                                Pre Registration Logs
                            </h1>
                            <p className="text-gray-600">Monitor and track Pre Registration activity</p>
                        </div>
                        <div onClick={() => router.get("/organizerLobby")} className='bg-red-500 text-white p-4 flex gap-x-3 rounded-md hover:bg-red-700 hover:cursor-pointer'>
                            <LayoutDashboardIcon />
                            <p>Go to Dashboard</p>
                        </div>
                    </div>

                    <div className="flex gap-6">
                        {/* Left Sidebar - Quiz Event Filter */}
                        <div className="w-80 flex-shrink-0">
                            <div className="bg-white rounded-xl shadow-lg p-6">
                                <h2 className="text-xl font-bold text-red-600 mb-2">Quiz Event</h2>
                                <p className="text-sm text-gray-600 mb-4">Select a quiz event to filter logs</p>
                                
                                <div className="relative mb-4">
                                    <input
                                        type="text"
                                        placeholder="Search quiz event..."
                                        className="w-full pl-10 pr-4 py-2 border border-gray-200 rounded-lg focus:ring-2 focus:ring-red-500 focus:border-red-500"
                                        value={lobbySearchTerm}
                                        onChange={(e) => setLobbySearchTerm(e.target.value)}
                                    />
                                    <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
                                </div>

                                <div className="space-y-2 max-h-96 overflow-y-auto">
                                    {filteredLobbies.length === 0 ? (
                                        <p className="text-gray-500 text-sm text-center py-4">No quiz events found</p>
                                    ) : (
                                        filteredLobbies.map((lobby) => (
                                            <button
                                                key={lobby.id}
                                                onClick={() => setSelectedLobby(lobby.id)}
                                                className={`w-full text-left px-4 py-3 rounded-lg transition-colors ${
                                                    selectedLobby === lobby.id
                                                        ? 'bg-orange-500 text-white'
                                                        : 'bg-gray-50 hover:bg-gray-100 text-gray-900'
                                                }`}
                                            >
                                                {lobby.name}
                                            </button>
                                        ))
                                    )}
                                </div>
                            </div>
                        </div>

                        {/* Right Content - Logs Table */}
                        <div className="flex-1">


                            {/* Stats Cards */}
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
                                <div className="bg-white rounded-xl shadow-lg border-l-4 border-red-500 p-6 hover:shadow-xl transition-shadow duration-300">
                                    <div className="flex items-center justify-between">
                                        <div>
                                            <p className="text-sm font-medium text-gray-600">Rejected</p>
                                            <p className="text-2xl font-bold text-gray-900">{filteredData?.filter(s => s.status == 1).length}</p>
                                        </div>
                                        <div className="p-3 bg-red-100 rounded-full">
                                            <BanIcon className="w-6 h-6 text-red-600" />
                                        </div>
                                    </div>
                                </div>

                                <div className="bg-white rounded-xl shadow-lg border-l-4 border-green-500 p-6 hover:shadow-xl transition-shadow duration-300">
                                    <div className="flex items-center justify-between">
                                        <div>
                                            <p className="text-sm font-medium text-gray-600">Approved</p>
                                            <p className="text-2xl font-bold text-gray-900">
                                                {filteredData?.filter(s => s.status == 2).length}
                                            </p>
                                        </div>
                                        <div className="p-3 bg-green-100 rounded-full">
                                            <UserRoundCheckIcon className="w-6 h-6 text-green-600" />
                                        </div>
                                    </div>
                                </div>
                            </div>

                            {/* Controls */}
                            <div className="bg-white rounded-xl shadow-lg p-6 mb-6">
                        <div className="flex flex-col sm:flex-row gap-4 items-center justify-between">
                            <div className="relative flex-1 max-w-md">
                                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-5 h-5" />
                                <input
                                    type="text"
                                    placeholder="Search by team name or team leader name..."
                                    className="w-full pl-10 pr-4 py-3 border border-gray-200 rounded-lg focus:ring-2 focus:ring-red-500 focus:border-red-500 transition-colors"
                                    value={searchTerm}
                                    onChange={(e) => setSearchTerm(e.target.value)}
                                />
                            </div>

                            <div className="flex items-center gap-2">
                                <Filter className="w-5 h-5 text-gray-500" />
                                <select
                                    className="border border-gray-200 rounded-lg px-4 py-3 focus:ring-2 focus:ring-red-500 focus:border-red-500 bg-white"
                                    value={filterActive}
                                    onChange={(e) => setFilterActive(e.target.value)}
                                >
                                    <option value="all">All Logs</option>
                                    <option value="active">Approved Only</option>
                                    <option value="ended">Rejected Only</option>
                                </select>
                            </div>
                        </div>
                    </div>

                            {/* Session Table */}
                            <div className="bg-white rounded-xl shadow-lg overflow-hidden">
                                <div className="p-4 border-b border-gray-200 flex items-center gap-2">
                                    <h3 className="text-lg font-semibold text-gray-900">
                                        Pre Registration Logs
                                    </h3>
                                    {selectedLobby && (
                                        <span className="text-sm text-gray-600">
                                            - {availableLobbies.find(l => l.id === selectedLobby)?.name || ''}
                                        </span>
                                    )}
                                </div>
                        <div className="overflow-x-auto pr-6 pb-4">
                            <table className="w-full min-w-[960px]">
                                <thead className="bg-gradient-to-r from-red-500 to-amber-500">
                                    <tr>
                                        <th className="px-6 py-4 text-left text-sm font-semibold text-white">Team Name</th>
                                        <th className="px-6 py-4 text-left text-sm font-semibold text-white">Team Leader</th>
                                        <th className="px-6 py-4 text-left text-sm font-semibold text-white">Email</th>
                                        <th className="px-6 py-4 text-left text-sm font-semibold text-white">Contact Number</th>
                                        <th className="px-6 py-4 text-left text-sm font-semibold text-white">Status</th>
                                        <th className="px-6 py-4 text-left text-sm font-semibold text-white">Reject / Approved Date</th>
                                        <th className="px-6 py-4 text-left text-sm font-semibold text-white">View</th>
                                        <th className="px-6 py-4 text-left text-sm font-semibold text-white">Comment</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-gray-200">
                                    {filteredData.map((session, index) => (
                                        <tr
                                            key={session.id}
                                            className={`hover:bg-red-50 transition-colors duration-200 ${index % 2 === 0 ? 'bg-white' : 'bg-gray-50'
                                                }`}
                                        >
                                            <td className="px-6 py-4">
                                                <div className="flex items-center w-fit truncate">
                                                    <div className="w-fit px-8 truncate h-8 bg-gradient-to-r from-red-400 to-amber-400 rounded-full flex items-center justify-center text-white font-semibold text-sm mr-3">
                                                        {session.participant?.team || 'N/A'}
                                                    </div>

                                                </div>
                                            </td>
                                            <td className="px-6 py-4">
                                                <div className="flex items-center w-fit truncate">
                                                    <User className="w-4 h-4 text-gray-400 mr-2" />
                                                    <span className="text-gray-900 font-medium">{session.participant?.team_leader || 'N/A'}</span>
                                                </div>
                                            </td>
                                            <td className="px-6 py-4">
                                                <span className="text-gray-900 font-medium break-words">{session.participant?.team_leader_email || 'N/A'}</span>
                                            </td>
                                            <td className="px-6 py-4">
                                                <div className="flex items-center">
                                                    <Hash className="w-4 h-4 text-gray-400 mr-2 flex-shrink-0" />
                                                    <span className="text-gray-900 font-mono break-words">{session.participant?.contact_number || 'N/A'}</span>
                                                </div>
                                            </td>
                                            <td className="px-6 py-4">
                                                <span className={`inline-flex items-center px-2 py-1 rounded-md text-sm font-medium ${session.status === 1
                                                    ? 'bg-red-100 text-red-800'
                                                    : 'bg-blue-100 text-blue-800'
                                                    }`}>
                                                    {session.status === 1 ? 'Rejected' : 'Approved'}
                                                </span>
                                            </td>
                                            <td className="px-6 py-4">
                                                <div className="flex items-center w-fit truncate">
                                                    <Clock className="w-4 h-4 text-gray-400 mr-2" />
                                                    <span className="text-gray-900 text-sm">{formatDateTime(session.created_at)}</span>
                                                </div>
                                            </td>
                                            <td className="px-6 py-4">
                                                <Button
                                                    size='sm'
                                                    className='bg-green-600 hover:bg-green-800 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed'
                                                    type="button"
                                                    disabled={!session.participant}
                                                    onClick={() => {
                                                        if (!session.participant) {
                                                            Swal.fire({
                                                                icon: 'error',
                                                                title: 'Error',
                                                                text: 'Participant data not available',
                                                                confirmButtonColor: '#16a34a'
                                                            });
                                                            return;
                                                        }
                                                        
                                                        const baseURL = window.location.origin + "/";
                             
                                                        let membersData = [];
                                                        try {
                                                            if (session.participant.members) {
                                                                membersData = JSON.parse(session.participant.members);
                                                            }
                                                        } catch (e) {
                                                            console.error('Error parsing members data:', e);
                                                            membersData = [];
                                                        }

             
                                                        // alert(JSON.stringify(membersData))
                                                        console.log(JSON.stringify(membersData))
                                                        // Example files array - replace with your actual data
                                                        const files = [
                                                            // {
                                                            //     url: 'https://example.com/document.pdf',
                                                            //     type: 'pdf',
                                                            //     name: 'Registration Form.pdf'
                                                            // },
                                                            {
                                                                url: '/storage/' + session.participant.student_id,
                                                                type: 'image',
                                                                name: `Valid Student ID (${session.participant.team_leader})`
                                                            },
                                                            {
                                                                url: '/storage/' + session.participant.registration_form,
                                                                type: 'image',
                                                                name: `Registration Form (${session.participant.team_leader})`
                                                            },
                                                            {
                                                                url: '/storage/' + session.participant.consent_form,
                                                                type: 'image',
                                                                name: `Consent Form (${session.participant.team_leader})`
                                                            }
                                                        ];

                                                        membersData.forEach(member => {
                                                            files.push(
                                                                {
                                                                    url: '/storage/' + member.requirements.studentId,
                                                                    type: 'image',
                                                                    name: `Valid Student ID (${member.name})`
                                                                },
                                                                {
                                                                    url: '/storage/' + member.requirements.registrationForm,
                                                                    type: 'image',
                                                                    name: `Registration Form (${member.name})`
                                                                },
                                                                {
                                                                    url: '/storage/' + member.requirements.consentForm,
                                                                    type: 'image',
                                                                    name: `Consent Form (${member.name})`
                                                                }
                                                            );
                                                        });
                                                        handleViewFiles(files);
                                                    }}
                                                >
                                                    <Eye className="w-4 h-4 text-white" />
                                                    <span>View</span>
                                                </Button>

                                            </td>
                                            <td className="px-6 py-4">
                                                <span className="text-gray-900 text-sm  w-fit  truncate">{session.comment}</span>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>

                        {filteredData.length === 0 && (
                            <div className="text-center py-12">
                                <div className="w-16 h-16 bg-red-100 rounded-full flex items-center justify-center mx-auto mb-4">
                                    <Search className="w-8 h-8 text-red-500" />
                                </div>
                                <h3 className="text-lg font-medium text-gray-900 mb-2">No sessions found</h3>
                                <p className="text-gray-500">Try adjusting your search criteria or filters.</p>
                            </div>
                        )}
                    </div>

                            {/* Footer */}
                            <div className="mt-8 text-center">
                                <p className="text-gray-500 text-sm">
                                    Showing {filteredData.length} of {selectedLobby ? filteredData.length : sessionData.length} sessions
                                </p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </AuthenticatedLayout>

    )
}

export default PreRegistrationLogs