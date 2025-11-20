import React, { useState } from 'react';
import { Search, User, Clock, MapPin, Calendar, Filter, LayoutDashboardIcon } from 'lucide-react';
import AuthenticatedLayout from '@/Layouts/AuthenticatedLayout';
import { Link, router, usePage } from '@inertiajs/react';
import { PageProps } from '@/types';
type Props = {}

const SessionHistory = (props: Props) => {

  const { logs } = usePage().props
  const { auth } = usePage<PageProps>().props
  const [searchTerm, setSearchTerm] = useState('');
  const [filterActive, setFilterActive] = useState('all');

  // Ensure logs is an array, default to empty array if undefined/null
  const sessionData = Array.isArray(logs) ? logs : []
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
    if (!session || !session.id) return false;

    // Students see only their own sessions
    if (auth?.user?.role === 2 && session.user_id !== auth?.user?.id) {
      return false;
    }

    // Teachers see only their own unless they are organizers
    if (auth?.user?.role === 1 && session.user_id !== auth?.user?.id) {
      return false;
    }

    const sessionId = session.id?.toString() || '';
    const ipAddress = session.ip_address || '';
    
    const matchesSearch = sessionId.includes(searchTerm) ||
      ipAddress.includes(searchTerm);

    if (filterActive === 'all') return matchesSearch;
    if (filterActive === 'active') return matchesSearch && !session.logout_timestamp;
    if (filterActive === 'ended') return matchesSearch && session.logout_timestamp;

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
  return (
    <AuthenticatedLayout>
      <div className="min-h-screen bg-gradient-to-br from-red-50 via-amber-50 to-yellow-50 p-6">

        <div className="max-w-7xl mx-auto">
          {/* Header */}
          <div className='flex justify-between items-center'>
            <div className="mb-8">
              <h1 className="text-4xl font-bold text-gray-900 mb-2 bg-gradient-to-r from-red-600 to-amber-600 bg-clip-text text-transparent">
                Session Logs
              </h1>
              <p className="text-gray-600">Monitor and track user session activity</p>
            </div>
            <button
              onClick={(e) => {
                e.preventDefault();
                e.stopPropagation();
                if (auth?.user?.role === 3) {
                  router.get("/organizerLobby");
                } else {
                  router.get("/dashboard");
                }
              }}
              className='bg-red-500 text-white p-4 flex gap-x-3 rounded-md hover:bg-red-700 hover:cursor-pointer'
              type="button"
            >
              <LayoutDashboardIcon />
              <p>Go to Dashboard</p>
            </button>

          </div>

          {/* Stats Cards */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
            <div className="bg-white rounded-xl shadow-lg border-l-4 border-red-500 p-6 hover:shadow-xl transition-shadow duration-300">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Total Sessions</p>
                  <p className="text-2xl font-bold text-gray-900">{sessionData.length}</p>
                </div>
                <div className="p-3 bg-red-100 rounded-full">
                  <User className="w-6 h-6 text-red-600" />
                </div>
              </div>
            </div>

            {auth?.user?.role === 3 && (
              <>
                <div className="bg-white rounded-xl shadow-lg border-l-4 border-green-500 p-6 hover:shadow-xl transition-shadow duration-300">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-gray-600">Active Sessions</p>
                      <p className="text-2xl font-bold text-gray-900">
                        {sessionData.filter(s => !s.logout_timestamp).length}
                      </p>
                    </div>
                    <div className="p-3 bg-green-100 rounded-full">
                      <Clock className="w-6 h-6 text-green-600" />
                    </div>
                  </div>
                </div>

                <div className="bg-white rounded-xl shadow-lg border-l-4 border-amber-500 p-6 hover:shadow-xl transition-shadow duration-300">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-gray-600">Unique Users</p>
                      <p className="text-2xl font-bold text-gray-900">
                        {new Set(sessionData.map(s => s.user_id)).size}
                      </p>
                    </div>
                    <div className="p-3 bg-amber-100 rounded-full">
                      <User className="w-6 h-6 text-amber-600" />
                    </div>
                  </div>
                </div>

                <div className="bg-white rounded-xl shadow-lg border-l-4 border-red-500 p-6 hover:shadow-xl transition-shadow duration-300">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-gray-600">Ended Sessions</p>
                      <p className="text-2xl font-bold text-gray-900">
                        {sessionData.filter(s => s.logout_timestamp).length}
                      </p>
                    </div>
                    <div className="p-3 bg-red-100 rounded-full">
                      <MapPin className="w-6 h-6 text-red-600" />
                    </div>
                  </div>
                </div>
              </>
            )}
          </div>

          {/* Controls */}
          <div className="bg-white rounded-xl shadow-lg p-6 mb-6">
            <div className="flex flex-col sm:flex-row gap-4 items-center justify-between">
              <div className="relative flex-1 max-w-md">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-5 h-5" />
                <input
                  type="text"
                  placeholder="Search by ID or IP address..."
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
                  <option value="all">All Sessions</option>
                  <option value="active">Active Only</option>
                  <option value="ended">Ended Only</option>
                </select>
              </div>
            </div>
          </div>

          {/* Session Table */}
          <div className="bg-white rounded-xl shadow-lg overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-gradient-to-r from-red-500 to-amber-500">
                  <tr>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-white">Session ID</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-white">User</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-white">Status</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-white">IP Address</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-white">Started</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-white">Ended</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-white">Duration</th>
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
                          <div className="w-8 h-8 bg-gradient-to-r from-red-400 to-amber-400 rounded-full flex items-center justify-center text-white font-semibold text-sm mr-3">
                            {session.id}
                          </div>
                          <span className="font-medium text-gray-900">#{session.id}</span>
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex items-center">
                          <User className="w-4 h-4 text-gray-400 mr-2" />
                          <span className="text-gray-900 font-medium">{session.user_name || `User ID: ${session.user_id || 'N/A'}`}</span>
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        {getStatusBadge(session.logout_timestamp)}
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex items-center">
                          <MapPin className="w-4 h-4 text-gray-400 mr-2" />
                          <span className="text-gray-900 font-mono">{session.ip_address}</span>
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex items-center">
                          <Calendar className="w-4 h-4 text-gray-400 mr-2" />
                          <span className="text-gray-900 text-sm">{formatDateTime(session.created_at)}</span>
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex items-center">
                          <Clock className="w-4 h-4 text-gray-400 mr-2" />
                          <span className="text-gray-900 text-sm">{formatDateTime(session.logout_timestamp)}</span>
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <span className={`inline-flex items-center px-2 py-1 rounded-md text-sm font-medium ${!session.logout_timestamp
                          ? 'bg-blue-100 text-blue-800'
                          : 'bg-gray-100 text-gray-800'
                          }`}>
                          {calculateDuration(session.created_at, session.logout_timestamp)}
                        </span>
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
              Showing {filteredData.length} of {sessionData.length} sessions
            </p>
          </div>
        </div>
      </div>
    </AuthenticatedLayout>

  )
}

export default SessionHistory