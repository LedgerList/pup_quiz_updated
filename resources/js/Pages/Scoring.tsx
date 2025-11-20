import React, { useEffect, useState } from 'react'
import AuthenticatedLayout from '@/Layouts/AuthenticatedLayout';
import { Search, User, Clock, MapPin, Filter, Save, FilePenLineIcon, Trash2Icon, Calendar1Icon, LayoutDashboardIcon, ChevronLeft } from 'lucide-react';
import { router, usePage } from '@inertiajs/react';
import { PageProps } from '@/types';
import axios from 'axios';
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/Components/ui/popover"
import { Calendar } from '@/Components/ui/calendar';
type Props = {}

const Scoring = (props: Props) => {
  const { logs, lobbies: initialLobbies } = usePage().props
  const { auth } = usePage<PageProps>().props
  const [searchTerm, setSearchTerm] = useState('');
  const [filterActive, setFilterActive] = useState('all');
  const [subjects, setSubjects] = useState([])
  const [lobbies, setLobbies] = useState<any[]>([])
  const [selectedLobby, setSelectedLobby] = useState<number | string>(0)
  const [lobbySearchTerm, setLobbySearchTerm] = useState('');
  const [filteredData, setFilteredData] = useState(logs);
  const [date, setDate] = React.useState<Date | undefined>(new Date())
  const sessionData = logs

  useEffect(() => {
    if (initialLobbies && initialLobbies.length > 0) {
      setLobbies(initialLobbies);
      if ((!selectedLobby || selectedLobby === 0) && initialLobbies[0]) {
        setSelectedLobby(initialLobbies[0].id);
      }
    } else {
      // Fallback to API call if not provided via props
      handleGetLobbies()
    }
  }, [initialLobbies]);

  const handleGetLobbies = async () => {
    try {
      const response = await axios.get("/getLobbyCategory")

      if (response.data) {
        setLobbies(response.data.lobbies)
        if ((!selectedLobby || selectedLobby === 0) && response.data?.lobbies[0]) {
          setSelectedLobby(response.data.lobbies[0].id)
        }
      }
    } catch (error) {
      console.log(error)
    }
  }

  const handleGetSubjects = async () => {
    if (!selectedLobby || selectedLobby === 0) return;
    try {
      const response = await axios.get(`/getLobbySubjects/${selectedLobby}`)

      if (response.data) {
        setSubjects(response.data.subjects)
        if (response.data?.subjects[0]) {
          setFilterActive(response.data.subjects[0].id)
        }
      }
    } catch (error) {
      console.log(error)
    }
  }

  useEffect(() => {
    handleGetSubjects()
  }, [selectedLobby])

  const filteredLobbies = lobbies.filter(lobby =>
    lobby.name.toLowerCase().includes(lobbySearchTerm.toLowerCase())
  );
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

  // let filteredData = sessionData.filter(session => {
  //   const matchesSearch = session.participant.team.toString().toLowerCase().includes(searchTerm.toLowerCase());


  //   return matchesSearch;
  // });

  useEffect(() => {
    let newData = sessionData;

    // Filter by selected lobby (through subject -> lobby relationship)
    if (selectedLobby && selectedLobby !== 0) {
      // Get subject IDs for the selected lobby
      const lobbySubjectIds = subjects.map((s: any) => s.id);
      newData = newData.filter(session => 
        lobbySubjectIds.includes(session.subject_id)
      );
    }

    // Filter by search term
    if (searchTerm) {
      newData = newData.filter(session =>
        session.participant?.team
          ?.toString()
          .toLowerCase()
          .includes(searchTerm.toLowerCase())
      );
    }

    // Filter by subject
    if (filterActive && filterActive !== 'all') {
      newData = newData.filter(
        session => session.subject_id?.toString() == filterActive
      );
    }

    // Filter by date
    if (date) {
      const phDateStr = new Intl.DateTimeFormat("en-PH", {
        timeZone: "Asia/Manila",
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
      }).format(new Date(date));

      newData = newData.filter(session => {
        const sessionDateStr = new Intl.DateTimeFormat("en-PH", {
          year: "numeric",
          month: "2-digit",
          day: "2-digit",
        }).format(new Date(session.created_at));

        return sessionDateStr === phDateStr;
      });
    }

    setFilteredData(newData);
  }, [searchTerm, sessionData, filterActive, selectedLobby, subjects, date])

  return (
    <AuthenticatedLayout>
      <div className="min-h-screen bg-gradient-to-br from-red-50 via-amber-50 to-yellow-50 p-6">
        <div className="max-w-7xl mx-auto">
          {/* Header */}
          <div className='flex justify-between items-center'>
            <div className="mb-8">
              <h1 className="text-4xl font-bold text-gray-900 mb-2 bg-gradient-to-r from-red-600 to-amber-600 bg-clip-text text-transparent">
                Leaderboard Logs
              </h1>
              <p className="text-gray-600">Monitor and track leaderboard. </p>
            </div>
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

          <div className="flex gap-6">
            {/* Left Sidebar - Quiz Event Filter */}
            <div className="w-80 flex-shrink-0">
              <div className="bg-white rounded-xl shadow-lg p-6">
                <h2 className="text-xl font-bold text-red-600 mb-2">Event Quiz Session</h2>
                <p className="text-sm text-gray-600 mb-4">Select an event quiz session</p>
                
                <div className="relative mb-4">
                  <input
                    type="text"
                    placeholder="Search event quiz session..."
                    className="w-full pl-10 pr-4 py-2 border border-gray-200 rounded-lg focus:ring-2 focus:ring-red-500 focus:border-red-500"
                    value={lobbySearchTerm}
                    onChange={(e) => setLobbySearchTerm(e.target.value)}
                  />
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
                </div>

                <div className="space-y-2 max-h-96 overflow-y-auto">
                  {filteredLobbies.length === 0 ? (
                    <p className="text-gray-500 text-sm text-center py-4">No event quiz sessions found</p>
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
                  <p className="text-sm font-medium text-gray-600">Total Event Lobbies</p>
                  <p className="text-2xl font-bold text-gray-900">{lobbies?.length || 0}</p>
                </div>
                <div className="p-3 bg-red-100 rounded-full">
                  <User className="w-6 h-6 text-red-600" />
                </div>
              </div>
            </div>



            <div className="bg-white rounded-xl shadow-lg border-l-4 border-green-500 p-6 hover:shadow-xl transition-shadow duration-300">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Subjects Covered</p>
                  <p className="text-2xl font-bold text-gray-900">
                    {subjects?.length || 0}
                  </p>
                </div>
                <div className="p-3 bg-green-100 rounded-full">
                  <Save className="w-6 h-6 text-green-600" />
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
                  placeholder="Search by Team name"
                  className="w-full pl-10 pr-4 py-3 border border-gray-200 rounded-lg focus:ring-2 focus:ring-red-500 focus:border-red-500 transition-colors"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                />
              </div>

              <div className="flex items-center gap-2">
                <Filter className="w-5 h-5 text-gray-500" />
                <select
                  className="border border-gray-200 rounded-lg px-7 py-3  focus:ring-2 focus:ring-red-500 focus:border-red-500 bg-white"
                  value={selectedLobby || 0}
                  onChange={(e) => setSelectedLobby(Number(e.target.value))}
                >
                  <option value={0} className=' capitalize'>Lobbies</option>
                  {
                    lobbies.map((lobby: any, index: number) =>
                      <option key={`${index}-lob`} value={lobby.id} className=' capitalize'>{lobby.name}</option>
                    )
                  }


                </select>

                <select
                  className="border border-gray-200 rounded-lg px-7 py-3  focus:ring-2 focus:ring-red-500 focus:border-red-500 bg-white"
                  value={filterActive || 'all'}
                  onChange={(e) => setFilterActive(e.target.value)}
                >
                  <option value="all" className=' capitalize'>Subjects</option>
                  {
                    subjects.map((subject: any, index: number) =>
                      <option key={`${index}-sub`} value={subject.id}>{subject.subject_name}</option>
                    )
                  }

                </select>

                <Popover>
                  <PopoverTrigger className=' flex items-center gap-x-2 border border-slate-300 px-3 py-3 rounded-md bg-red-400 hover-bg-red-400 text-white'>
                    <>
                      <Calendar1Icon className='w-5 h-5' />
                      Session Date
                    </>

                  </PopoverTrigger>
                  <PopoverContent>   <Calendar
                    mode="single"
                    selected={date}
                    onSelect={setDate}

                    captionLayout="dropdown"
                  /></PopoverContent>
                </Popover>

              </div>
            </div>
          </div>

              {/* Session Table */}
              <div className="bg-white rounded-xl shadow-lg overflow-hidden">
                <div className="p-4 border-b border-gray-200 flex items-center gap-2">
                  <h3 className="text-lg font-semibold text-gray-900">
                    Event Quiz Results
                  </h3>
                  {selectedLobby && selectedLobby !== 0 && (
                    <span className="text-sm text-gray-600">
                      - {lobbies.find(l => l.id === selectedLobby)?.name || ''}
                    </span>
                  )}
                </div>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-gradient-to-r from-red-500 to-amber-500">
                  <tr>

                    <th className="px-6 py-4 text-left text-sm font-semibold text-white">User ID</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-white">Team Name</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-white">Total Score</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-white">Place</th>

                    <th className="px-6 py-4 text-left text-sm font-semibold text-white">Date Time</th>

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
                        <div className="flex items-center">
                          <User className="w-4 h-4 text-gray-400 mr-2" />
                          <span className="text-gray-900 font-medium">{auth.user.name}</span>
                        </div>
                      </td>
                      <td className="px-6 py-4 capitalize" >
                        {session.participant.team}
                      </td>
                      <td className="px-6 py-4 capitalize" >
                        {session.total_score}
                      </td>
                      <td className="px-6 py-4 capitalize" >
                        {session.place} Place
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

            {filteredData.length === 0 && (
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

export default Scoring