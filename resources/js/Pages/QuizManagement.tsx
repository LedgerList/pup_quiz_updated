import React, { useState, useEffect } from 'react'
import AuthenticatedLayout from '@/Layouts/AuthenticatedLayout';
import { Search, User, Clock, MapPin, Calendar, Filter, Save, FilePenLineIcon, Trash2Icon, LayoutDashboardIcon, ChevronLeft, ChevronRight, ChevronDown, ChevronUp, FileSpreadsheet } from 'lucide-react';
import { router, usePage } from '@inertiajs/react';
import { PageProps } from '@/types';
import axios from 'axios';
import Swal from 'sweetalert2';
type Props = {}

const QuizManagement = (props: Props) => {
  const { logs, lobbies } = usePage().props
  const { auth } = usePage<PageProps>().props
  const [searchTerm, setSearchTerm] = useState('');
  const [filterActive, setFilterActive] = useState('all');
  const [selectedLobby, setSelectedLobby] = useState<number | 'all'>('all');
  const [lobbySearchTerm, setLobbySearchTerm] = useState('');
  const [availableLobbies, setAvailableLobbies] = useState<any[]>([]);
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState(false);
  const [isGeneratingReport, setIsGeneratingReport] = useState(false);

  useEffect(() => {
    if (lobbies && lobbies.length > 0) {
      setAvailableLobbies(lobbies);
    }
  }, [lobbies]);

  // Filter lobbies based on search term
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

  // Filter logs by selected lobby (through question -> subject -> lobby relationship)
  const filteredData = sessionData.filter(session => {
    // Filter by selected lobby if one is selected
    if (selectedLobby !== 'all' && selectedLobby) {
      const questionLobbyId = session.question?.subject?.lobby_id;
      if (questionLobbyId !== selectedLobby) {
        return false;
      }
    }

    const matchesSearch = session.question?.question?.toString().includes(searchTerm) ||
      session.question?.difficulty?.includes(searchTerm);
    if (filterActive === 'all') return matchesSearch;
    if (filterActive === 'created') return matchesSearch && session.action == 0;
    if (filterActive === 'edited') return matchesSearch && session.action == 1;
    if (filterActive === 'deleted') return matchesSearch && session.action == 2;

    return matchesSearch;
  });

  // Deduplicate questions - keep only the most recent log entry for each question
  const uniqueQuestions = filteredData.reduce((acc: any[], current: any) => {
    const questionId = current.question?.id;
    if (!questionId) return acc;

    const existingIndex = acc.findIndex((item: any) => item.question?.id === questionId);
    
    if (existingIndex === -1) {
      // Question not found, add it
      acc.push(current);
    } else {
      // Question exists, keep the one with the most recent timestamp
      const existing = acc[existingIndex];
      const currentTime = new Date(current.created_at).getTime();
      const existingTime = new Date(existing.created_at).getTime();
      
      // If current is deleted, always replace (deleted is the final state)
      if (current.action === 2) {
        acc[existingIndex] = current;
      } else if (existing.action !== 2 && currentTime > existingTime) {
        // Only replace if existing is not deleted and current is more recent
        acc[existingIndex] = current;
      }
      // If existing is deleted, keep it (don't replace with older non-deleted entries)
    }
    
    return acc;
  }, []);

  // Sort by most recent first
  const sortedUniqueQuestions = uniqueQuestions.sort((a: any, b: any) => {
    return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
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

  const handleGenerateReport = async () => {
    setIsGeneratingReport(true);
    try {
      const lobbyIdParam = selectedLobby !== 'all' && selectedLobby ? `/${selectedLobby}` : '';
      const response = await axios.get(`/report/quiz-management${lobbyIdParam}`, {
        responseType: 'blob',
      });

      if (response.status === 200) {
        let filename = 'quiz_management_logs.xlsx';
        const contentDisposition = response.headers['content-disposition'];
        if (contentDisposition) {
          const filenameMatch = contentDisposition.match(/filename="?([^"]+)"?/);
          if (filenameMatch && filenameMatch[1]) {
            filename = filenameMatch[1];
          }
        }

        const url = window.URL.createObjectURL(new Blob([response.data]));
        const link = document.createElement('a');
        link.href = url;
        link.setAttribute('download', filename);
        document.body.appendChild(link);
        link.click();
        link.remove();
        window.URL.revokeObjectURL(url);

        Swal.fire({
          toast: true,
          position: 'top-end',
          icon: 'success',
          title: 'Report downloaded successfully!',
          showConfirmButton: false,
          timer: 3000,
          timerProgressBar: true,
        });
      }
    } catch (error: any) {
      console.error('Error during report download:', error);
      let errorMessage = 'An error occurred during download.';
      
      if (error.response) {
        errorMessage = error.response.data?.message || `Server error: ${error.response.status}`;
      } else if (error.request) {
        errorMessage = 'No response from server. Please check your connection.';
      } else {
        errorMessage = error.message || 'An unexpected error occurred.';
      }
      
      Swal.fire({
        toast: true,
        position: 'top-end',
        icon: 'error',
        title: errorMessage,
        showConfirmButton: false,
        timer: 4000,
        timerProgressBar: true,
      });
    } finally {
      setIsGeneratingReport(false);
    }
  };
  return (
    <AuthenticatedLayout>
      <div className="min-h-screen bg-gradient-to-br from-red-50 via-amber-50 to-yellow-50 p-6">
        <div className="max-w-7xl mx-auto">
          {/* Header */}
         <div className='flex justify-between items-center'>    
            <div className="mb-8">
              <h1 className="text-4xl font-bold text-gray-900 mb-2 bg-gradient-to-r from-red-600 to-amber-600 bg-clip-text text-transparent">
                Event Quiz Logs
              </h1>
              <p className="text-gray-600">Monitor and track quiz activity</p>
            </div>

            <div className="flex gap-3">
              <button
                onClick={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                  handleGenerateReport();
                }}
                disabled={isGeneratingReport}
                className='bg-orange-600 text-white p-4 flex gap-x-3 rounded-md hover:bg-orange-700 hover:cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed transition-colors'
                type="button"
              >
                <FileSpreadsheet className="w-5 h-5" />
                <p>{isGeneratingReport ? 'Generating...' : 'Generate Report'}</p>
              </button>
              <button
                onClick={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                  router.get("/organizerLobby");
                }}
                className='bg-red-500 text-white p-4 flex gap-x-3 rounded-md hover:bg-red-700 hover:cursor-pointer'
                type="button"
              >
                <LayoutDashboardIcon />
                <p>Go to Dashboard</p>
              </button>
            </div>
          </div>

          <div className="flex gap-6">
            {/* Left Sidebar - Quiz Event Filter (Collapsible) */}
            <div className={`${isSidebarCollapsed ? 'w-0' : 'w-80'} flex-shrink-0 transition-all duration-300 overflow-hidden`}>
              <div className="bg-white rounded-xl shadow-lg p-6">
                <div className="flex items-center justify-between mb-4">
                  <div>
                    <h2 className="text-xl font-bold text-red-600 mb-2">Event Quiz Sessions</h2>
                    <p className="text-sm text-gray-600">Select a live event quiz session to filter quiz logs</p>
                  </div>
                  <button
                    onClick={() => setIsSidebarCollapsed(true)}
                    className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
                    type="button"
                    title="Collapse sidebar"
                  >
                    <ChevronLeft className="w-5 h-5 text-gray-600" />
                  </button>
                </div>
                
                {/* Search Input */}
                <div className="relative mb-4">
                  <input
                    type="text"
                    placeholder="Search live session..."
                    className="w-full pl-10 pr-4 py-2 border border-gray-200 rounded-lg focus:ring-2 focus:ring-red-500 focus:border-red-500"
                    value={lobbySearchTerm}
                    onChange={(e) => setLobbySearchTerm(e.target.value)}
                  />
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
                </div>

                {/* Quiz Event List */}
                <div className="space-y-2 max-h-96 overflow-y-auto">
                  <button
                    onClick={() => setSelectedLobby('all')}
                    className={`w-full text-left px-4 py-3 rounded-lg transition-colors ${selectedLobby === 'all'
                      ? 'bg-orange-500 text-white'
                      : 'bg-gray-50 hover:bg-gray-100 text-gray-900'
                      }`}
                    type="button"
                  >
                    All Event Quiz Sessions
                  </button>
                  {filteredLobbies.length === 0 ? (
                    <p className="text-gray-500 text-sm text-center py-4">No live sessions found</p>
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
                        type="button"
                      >
                        {lobby.name}
                      </button>
                    ))
                  )}
                </div>
              </div>
            </div>

            {/* Collapse/Expand Button when sidebar is collapsed */}
            {isSidebarCollapsed && (
              <button
                onClick={() => setIsSidebarCollapsed(false)}
                className="self-start p-2 bg-white rounded-lg shadow-lg hover:bg-gray-50 transition-colors"
                type="button"
                title="Expand sidebar"
              >
                <ChevronRight className="w-5 h-5 text-gray-600" />
              </button>
            )}

            {/* Right Content - Logs Table */}
            <div className="flex-1">
    
              {/* Stats Cards */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
                <div className="bg-white rounded-xl shadow-lg border-l-4 border-red-500 p-6 hover:shadow-xl transition-shadow duration-300">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-gray-600">Total Questions</p>
                      <p className="text-2xl font-bold text-gray-900">{sortedUniqueQuestions.length}</p>
                    </div>
                    <div className="p-3 bg-red-100 rounded-full">
                      <User className="w-6 h-6 text-red-600" />
                    </div>
                  </div>
                </div>

                <div className="bg-white rounded-xl shadow-lg border-l-4 border-green-500 p-6 hover:shadow-xl transition-shadow duration-300">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-gray-600">Created Questions</p>
                      <p className="text-2xl font-bold text-gray-900">
                        {sortedUniqueQuestions.filter(s => s.action == 0).length}
                      </p>
                    </div>
                    <div className="p-3 bg-green-100 rounded-full">
                      <Save className="w-6 h-6 text-green-600" />
                    </div>
                  </div>
                </div>
                <div className="bg-white rounded-xl shadow-lg border-l-4 border-red-500 p-6 hover:shadow-xl transition-shadow duration-300">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-gray-600">Edited Questions</p>
                      <p className="text-2xl font-bold text-gray-900">
                        {sortedUniqueQuestions.filter(s => s.action == 1).length}
                      </p>
                    </div>
                    <div className="p-3 bg-yellow-100 rounded-full">
                      <FilePenLineIcon className="w-6 h-6 text-yellow-600" />
                    </div>
                  </div>
                </div>
                <div className="bg-white rounded-xl shadow-lg border-l-4 border-red-500 p-6 hover:shadow-xl transition-shadow duration-300">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-gray-600">Deleted Questions</p>
                      <p className="text-2xl font-bold text-gray-900">
                        {sortedUniqueQuestions.filter(s => s.action == 2).length}
                      </p>
                    </div>
                    <div className="p-3 bg-red-100 rounded-full">
                      <Trash2Icon className="w-6 h-6 text-red-600" />
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
                  placeholder="Search quiz questions..."
                  className="w-full pl-10 pr-4 py-3 border border-gray-200 rounded-lg focus:ring-2 focus:ring-red-500 focus:border-red-500 transition-colors"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                />
              </div>

              <div className="flex items-center gap-2">
                <Filter className="w-5 h-5 text-gray-500" />
                <select
                  className="border border-gray-200 rounded-lg px-7 py-3  focus:ring-2 focus:ring-red-500 focus:border-red-500 bg-white"
                  value={filterActive}
                  onChange={(e) => setFilterActive(e.target.value)}
                >
                  <option value="all">All</option>
                  <option value="created">Created</option>
                  <option value="edited">Edited</option>
                  <option value="deleted">Deleted</option>
                </select>
              </div>
            </div>
          </div>

              {/* Session Table */}
              <div className="bg-white rounded-xl shadow-lg overflow-hidden">
                <div className="p-4 border-b border-gray-200 flex items-center gap-2">
                  <h3 className="text-lg font-semibold text-gray-900">
                    Manage Quiz Questions
                  </h3>
                  {selectedLobby !== 'all' && selectedLobby && (
                    <span className="text-sm text-gray-600">
                      - Live Event Quiz Session: {availableLobbies.find(l => l.id === selectedLobby)?.name || ''}
                    </span>
                  )}
                </div>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-gradient-to-r from-orange-500 to-amber-500">
                  <tr>

                    <th className="px-6 py-4 text-left text-sm font-semibold text-white">User ID</th>

                    <th className="px-6 py-4 text-left text-sm font-semibold text-white">Question Name</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-white">Question Type</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-white">Question Level</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-white">Action</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-white">Date Time</th>

                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200">
                  {sortedUniqueQuestions.map((session, index) => (
                    <tr
                      key={session.id}
                      className={`hover:bg-red-50 transition-colors duration-200 ${index % 2 === 0 ? 'bg-white' : 'bg-gray-50'
                        }`}
                    >

                      <td className="px-6 py-4">
                        <div className="flex items-center">
                          <User className="w-4 h-4 text-gray-400 mr-2" />
                          <span className="text-gray-900 font-medium">{auth.user.name}</span>
                        </div>
                      </td>
                      <td className="px-6 py-4 capitalize" >
                        {session.question.question}
                      </td>

                      <td className="px-6 py-4 capitalize">
                        {session.question.type}
                      </td>
                      <td className="px-6 py-4 capitalize">
                        {session.question.difficulty}
                      </td>
                      <td className="px-6 py-4">

                        <span className={`inline-flex items-center px-2 py-1 rounded-md text-sm font-medium ${session.action == 0
                          ? 'bg-blue-100 text-blue-800'
                          : session.action == 1 ? 'bg-yellow-100 text-yellow-800' : 'bg-red-100 text-red-800'
                          }`}>
                          {session.action == 0
                            ? 'Create'
                            : session.action == 1 ? 'Edit' : 'Delete'
                          }
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex items-center">
                          <Clock className="w-4 h-4 text-gray-400 mr-2" />
                          <span className="text-gray-900 text-sm">{formatDateTime(session.created_at)}</span>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {sortedUniqueQuestions.length === 0 && (
              <div className="text-center py-12">
                <div className="w-16 h-16 bg-red-100 rounded-full flex items-center justify-center mx-auto mb-4">
                  <Search className="w-8 h-8 text-red-500" />
                </div>
                <h3 className="text-lg font-medium text-gray-900 mb-2">No data found</h3>
                <p className="text-gray-500">Try adjusting your search criteria or filters.</p>
              </div>
            )}
          </div>

              {/* Footer */}
              <div className="mt-8 text-center">
                <p className="text-gray-500 text-sm">
                  Showing {sortedUniqueQuestions.length} of {selectedLobby ? sortedUniqueQuestions.length : sessionData.length} questions
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </AuthenticatedLayout>

  )
}

export default QuizManagement