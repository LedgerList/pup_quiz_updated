import React, { useState, useMemo } from 'react';
import AuthenticatedLayout from '@/Layouts/AuthenticatedLayout';
import { router, usePage } from '@inertiajs/react';
import { PageProps } from '@/types';
import { 
    LayoutDashboardIcon,
    Search,
    Filter,
    ChevronDown,
    ChevronUp,
    Clock,
    User,
    FileText,
    Trophy,
    ClipboardList,
    UserCheck,
    Users,
    Download,
    Calendar
} from 'lucide-react';

type Props = {}

interface AuditLog {
    id: number;
    type: string;
    user_name: string;
    action: string;
    description: string;
    ip_address?: string;
    timestamp: string;
    lobby_id?: number;
    lobby_name?: string;
}

const AuditTrails = (props: Props) => {
    const { allLogs, lobbies } = usePage().props as any;
    const { auth } = usePage<PageProps>().props;
    const [searchTerm, setSearchTerm] = useState('');
    const [filterType, setFilterType] = useState('all');
    const [filterUser, setFilterUser] = useState('all');
    const [expandedLobbies, setExpandedLobbies] = useState<Set<number>>(new Set());
    const [dateFrom, setDateFrom] = useState('');
    const [dateTo, setDateTo] = useState('');

    // Get all unique users from logs
    const allUsers = useMemo(() => {
        const users = new Set<string>();
        allLogs?.forEach((log: AuditLog) => {
            if (log.user_name) users.add(log.user_name);
        });
        return Array.from(users);
    }, [allLogs]);

    // Get all unique types from logs
    const allTypes = useMemo(() => {
        const types = new Set<string>();
        allLogs?.forEach((log: AuditLog) => {
            if (log.type) types.add(log.type);
        });
        return Array.from(types);
    }, [allLogs]);

    // Group logs by lobby
    const logsByLobby = useMemo(() => {
        const grouped: { [key: number]: { lobby: any; logs: AuditLog[] } } = {};
        const noLobbyLogs: AuditLog[] = [];

        allLogs?.forEach((log: AuditLog) => {
            if (log.lobby_id) {
                if (!grouped[log.lobby_id]) {
                    const lobby = lobbies?.find((l: any) => l.id === log.lobby_id);
                    grouped[log.lobby_id] = {
                        lobby: lobby || { id: log.lobby_id, name: log.lobby_name || 'Unknown Lobby' },
                        logs: []
                    };
                }
                grouped[log.lobby_id].logs.push(log);
            } else {
                noLobbyLogs.push(log);
            }
        });

        // Add logs without lobby to a special group
        if (noLobbyLogs.length > 0) {
            grouped[0] = {
                lobby: { id: 0, name: 'General Logs' },
                logs: noLobbyLogs
            };
        }

        return grouped;
    }, [allLogs, lobbies]);

    // Filter logs
    const filteredLogsByLobby = useMemo(() => {
        const filtered: { [key: number]: { lobby: any; logs: AuditLog[] } } = {};

        Object.keys(logsByLobby).forEach((lobbyIdStr) => {
            const lobbyId = parseInt(lobbyIdStr);
            const { lobby, logs } = logsByLobby[lobbyId];

            let filteredLogs = logs.filter((log: AuditLog) => {
                // Search filter
                const matchesSearch = !searchTerm || 
                    log.user_name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
                    log.description?.toLowerCase().includes(searchTerm.toLowerCase()) ||
                    log.action?.toLowerCase().includes(searchTerm.toLowerCase()) ||
                    log.ip_address?.includes(searchTerm);

                // Type filter
                const matchesType = filterType === 'all' || log.type === filterType;

                // User filter
                const matchesUser = filterUser === 'all' || log.user_name === filterUser;

                // Date filters
                let matchesDate = true;
                if (dateFrom || dateTo) {
                    const logDate = new Date(log.timestamp);
                    if (dateFrom) {
                        const fromDate = new Date(dateFrom);
                        fromDate.setHours(0, 0, 0, 0);
                        if (logDate < fromDate) matchesDate = false;
                    }
                    if (dateTo) {
                        const toDate = new Date(dateTo);
                        toDate.setHours(23, 59, 59, 999);
                        if (logDate > toDate) matchesDate = false;
                    }
                }

                return matchesSearch && matchesType && matchesUser && matchesDate;
            });

            if (filteredLogs.length > 0) {
                filtered[lobbyId] = { lobby, logs: filteredLogs };
            }
        });

        return filtered;
    }, [logsByLobby, searchTerm, filterType, filterUser, dateFrom, dateTo]);

    // Calculate summary stats
    const summaryStats = useMemo(() => {
        const allFilteredLogs = Object.values(filteredLogsByLobby).flatMap(g => g.logs);
        return {
            sessions: allFilteredLogs.filter(l => l.type === 'Session History').length,
            quizzes: allFilteredLogs.filter(l => l.type === 'Quiz Management').length,
            participants: allFilteredLogs.filter(l => l.type === 'Lobby Management').length,
            leaderboard: allFilteredLogs.filter(l => l.type === 'Scoring / Results').length,
            registration: allFilteredLogs.filter(l => l.type === 'Pre-Registration Logs').length,
            quizSession: allFilteredLogs.filter(l => l.type === 'Question Statistics').length,
            total: allFilteredLogs.length
        };
    }, [filteredLogsByLobby]);

    const toggleLobby = (lobbyId: number) => {
        const newExpanded = new Set(expandedLobbies);
        if (newExpanded.has(lobbyId)) {
            newExpanded.delete(lobbyId);
        } else {
            newExpanded.add(lobbyId);
        }
        setExpandedLobbies(newExpanded);
    };

    const expandAll = () => {
        const allLobbyIds = Object.keys(filteredLogsByLobby).map(id => parseInt(id));
        setExpandedLobbies(new Set(allLobbyIds));
    };

    const collapseAll = () => {
        setExpandedLobbies(new Set());
    };

    const formatDateTime = (timestamp: string) => {
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

    const getActionBadgeColor = (action: string) => {
        const actionLower = action?.toLowerCase() || '';
        if (actionLower.includes('create') || actionLower.includes('login') || actionLower === 'approved') {
            return 'bg-blue-100 text-blue-800';
        }
        if (actionLower.includes('edit') || actionLower.includes('update')) {
            return 'bg-yellow-100 text-yellow-800';
        }
        if (actionLower.includes('delete') || actionLower.includes('logout') || actionLower === 'rejected') {
            return 'bg-red-100 text-red-800';
        }
        if (actionLower.includes('active')) {
            return 'bg-green-100 text-green-800';
        }
        return 'bg-gray-100 text-gray-800';
    };

    const getTypeIcon = (type: string) => {
        switch (type) {
            case 'Session History':
                return Clock;
            case 'Lobby Management':
                return Users;
            case 'Quiz Management':
                return ClipboardList;
            case 'Scoring / Results':
                return Trophy;
            case 'Question Statistics':
                return FileText;
            case 'Pre-Registration Logs':
                return UserCheck;
            default:
                return FileText;
        }
    };

    const exportToCSV = () => {
        const allLogs = Object.values(filteredLogsByLobby).flatMap(g => g.logs);
        const headers = ['Type', 'User', 'Action', 'Description', 'IP Address', 'Timestamp', 'Lobby'];
        const rows = allLogs.map(log => [
            log.type || '',
            log.user_name || '',
            log.action || '',
            log.description || '',
            log.ip_address || '',
            log.timestamp || '',
            log.lobby_name || 'General'
        ]);

        const csvContent = [
            headers.join(','),
            ...rows.map(row => row.map(cell => `"${cell}"`).join(','))
        ].join('\n');

        const blob = new Blob([csvContent], { type: 'text/csv' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `audit-trails-${new Date().toISOString().split('T')[0]}.csv`;
        a.click();
        window.URL.revokeObjectURL(url);
    };

    return (
        <AuthenticatedLayout>
            <div className="min-h-screen bg-gradient-to-br from-red-50 via-amber-50 to-yellow-50 p-6">
                <div className="max-w-7xl mx-auto">
                    {/* Header */}
                    <div className='flex justify-between items-center mb-8'>
                        <div>
                            <h1 className="text-4xl font-bold text-gray-900 mb-2 bg-gradient-to-r from-red-600 to-amber-600 bg-clip-text text-transparent">
                                Audit Trails & Reports
                            </h1>
                            <p className="text-gray-600">System logs and reports for monitoring activities</p>
                        </div>

                        <div className="flex gap-3">
                            <button
                                onClick={exportToCSV}
                                className='bg-green-500 text-white p-4 flex gap-x-3 rounded-md hover:bg-green-700 hover:cursor-pointer transition-colors'
                            >
                                <Download className="w-5 h-5" />
                                <p>Export CSV</p>
                            </button>
                            <div 
                                onClick={() => router.get("/organizerLobby")} 
                                className='bg-red-500 text-white p-4 flex gap-x-3 rounded-md hover:bg-red-700 hover:cursor-pointer transition-colors'
                            >
                                <LayoutDashboardIcon />
                                <p>Go to Dashboard</p>
                            </div>
                        </div>
                    </div>

                    {/* Summary Stats Cards */}
                    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-6">
                        <div className="bg-white rounded-xl shadow-lg border-l-4 border-blue-500 p-4">
                            <div className="flex items-center justify-between">
                                <div>
                                    <p className="text-xs font-medium text-gray-600">Sessions</p>
                                    <p className="text-2xl font-bold text-gray-900">{summaryStats.sessions}</p>
                                </div>
                                <Clock className="w-8 h-8 text-blue-500" />
                            </div>
                        </div>
                        <div className="bg-white rounded-xl shadow-lg border-l-4 border-purple-500 p-4">
                            <div className="flex items-center justify-between">
                                <div>
                                    <p className="text-xs font-medium text-gray-600">Quizzes</p>
                                    <p className="text-2xl font-bold text-gray-900">{summaryStats.quizzes}</p>
                                </div>
                                <ClipboardList className="w-8 h-8 text-purple-500" />
                            </div>
                        </div>
                        <div className="bg-white rounded-xl shadow-lg border-l-4 border-green-500 p-4">
                            <div className="flex items-center justify-between">
                                <div>
                                    <p className="text-xs font-medium text-gray-600">Participants</p>
                                    <p className="text-2xl font-bold text-gray-900">{summaryStats.participants}</p>
                                </div>
                                <Users className="w-8 h-8 text-green-500" />
                            </div>
                        </div>
                        <div className="bg-white rounded-xl shadow-lg border-l-4 border-amber-500 p-4">
                            <div className="flex items-center justify-between">
                                <div>
                                    <p className="text-xs font-medium text-gray-600">Leaderboard</p>
                                    <p className="text-2xl font-bold text-gray-900">{summaryStats.leaderboard}</p>
                                </div>
                                <Trophy className="w-8 h-8 text-amber-500" />
                            </div>
                        </div>
                        <div className="bg-white rounded-xl shadow-lg border-l-4 border-pink-500 p-4">
                            <div className="flex items-center justify-between">
                                <div>
                                    <p className="text-xs font-medium text-gray-600">Registration</p>
                                    <p className="text-2xl font-bold text-gray-900">{summaryStats.registration}</p>
                                </div>
                                <UserCheck className="w-8 h-8 text-pink-500" />
                            </div>
                        </div>
                        <div className="bg-white rounded-xl shadow-lg border-l-4 border-red-500 p-4">
                            <div className="flex items-center justify-between">
                                <div>
                                    <p className="text-xs font-medium text-gray-600">Quiz Session</p>
                                    <p className="text-2xl font-bold text-gray-900">{summaryStats.quizSession}</p>
                                </div>
                                <FileText className="w-8 h-8 text-red-500" />
                            </div>
                        </div>
                    </div>

                    {/* Filters */}
                    <div className="bg-white rounded-xl shadow-lg p-6 mb-6">
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
                            <div className="relative">
                                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-5 h-5" />
                                <input
                                    type="text"
                                    placeholder="Search activities..."
                                    className="w-full pl-10 pr-4 py-3 border border-gray-200 rounded-lg focus:ring-2 focus:ring-red-500 focus:border-red-500"
                                    value={searchTerm}
                                    onChange={(e) => setSearchTerm(e.target.value)}
                                />
                            </div>

                            <div className="flex items-center gap-2">
                                <Filter className="w-5 h-5 text-gray-500" />
                                <select
                                    className="w-full border border-gray-200 rounded-lg px-4 py-3 focus:ring-2 focus:ring-red-500 focus:border-red-500 bg-white"
                                    value={filterType}
                                    onChange={(e) => setFilterType(e.target.value)}
                                >
                                    <option value="all">All Types</option>
                                    {allTypes.map((type) => (
                                        <option key={type} value={type}>{type}</option>
                                    ))}
                                </select>
                            </div>

                            <div className="flex items-center gap-2">
                                <User className="w-5 h-5 text-gray-500" />
                                <select
                                    className="w-full border border-gray-200 rounded-lg px-4 py-3 focus:ring-2 focus:ring-red-500 focus:border-red-500 bg-white"
                                    value={filterUser}
                                    onChange={(e) => setFilterUser(e.target.value)}
                                >
                                    <option value="all">All Users</option>
                                    {allUsers.map((user) => (
                                        <option key={user} value={user}>{user}</option>
                                    ))}
                                </select>
                            </div>

                            <div className="flex items-center gap-2">
                                <Calendar className="w-5 h-5 text-gray-500" />
                                <input
                                    type="date"
                                    className="w-full border border-gray-200 rounded-lg px-4 py-3 focus:ring-2 focus:ring-red-500 focus:border-red-500"
                                    value={dateFrom}
                                    onChange={(e) => setDateFrom(e.target.value)}
                                    placeholder="From"
                                />
                            </div>

                            <div className="flex items-center gap-2">
                                <Calendar className="w-5 h-5 text-gray-500" />
                                <input
                                    type="date"
                                    className="w-full border border-gray-200 rounded-lg px-4 py-3 focus:ring-2 focus:ring-red-500 focus:border-red-500"
                                    value={dateTo}
                                    onChange={(e) => setDateTo(e.target.value)}
                                    placeholder="To"
                                />
                            </div>
                        </div>

                        <div className="mt-4 flex justify-between items-center">
                            <div className="flex gap-2">
                                <button
                                    onClick={expandAll}
                                    className="px-4 py-2 text-sm text-gray-700 bg-gray-100 rounded-lg hover:bg-gray-200 transition-colors"
                                >
                                    Expand All
                                </button>
                                <button
                                    onClick={collapseAll}
                                    className="px-4 py-2 text-sm text-gray-700 bg-gray-100 rounded-lg hover:bg-gray-200 transition-colors"
                                >
                                    Collapse All
                                </button>
                            </div>
                            <p className="text-sm text-gray-600">
                                Showing {summaryStats.total} logs
                            </p>
                        </div>
                    </div>

                    {/* Logs by Lobby - Collapsible Sections */}
                    <div className="space-y-4">
                        {Object.keys(filteredLogsByLobby).length === 0 ? (
                            <div className="bg-white rounded-xl shadow-lg p-12 text-center">
                                <Search className="w-16 h-16 text-gray-400 mx-auto mb-4" />
                                <h3 className="text-lg font-medium text-gray-900 mb-2">No logs found</h3>
                                <p className="text-gray-500">Try adjusting your search criteria or filters.</p>
                            </div>
                        ) : (
                            Object.values(filteredLogsByLobby)
                                .sort((a, b) => {
                                    // Sort: General Logs first, then by lobby name
                                    if (a.lobby.id === 0) return -1;
                                    if (b.lobby.id === 0) return 1;
                                    return a.lobby.name.localeCompare(b.lobby.name);
                                })
                                .map(({ lobby, logs }) => {
                                    const isExpanded = expandedLobbies.has(lobby.id);
                                    const TypeIcon = getTypeIcon('');

                                    return (
                                        <div key={lobby.id} className="bg-white rounded-xl shadow-lg overflow-hidden">
                                            {/* Lobby Header - Collapsible */}
                                            <button
                                                onClick={() => toggleLobby(lobby.id)}
                                                className="w-full px-6 py-4 bg-gradient-to-r from-orange-500 to-amber-500 text-white flex items-center justify-between hover:from-orange-600 hover:to-amber-600 transition-colors"
                                            >
                                                <div className="flex items-center gap-3">
                                                    {isExpanded ? (
                                                        <ChevronUp className="w-5 h-5" />
                                                    ) : (
                                                        <ChevronDown className="w-5 h-5" />
                                                    )}
                                                    <h3 className="text-lg font-semibold">{lobby.name}</h3>
                                                    <span className="px-3 py-1 bg-white/20 rounded-full text-sm">
                                                        {logs.length} logs
                                                    </span>
                                                </div>
                                            </button>

                                            {/* Logs Table - Collapsible Content */}
                                            {isExpanded && (
                                                <div className="overflow-x-auto">
                                                    <table className="w-full">
                                                        <thead className="bg-gray-50">
                                                            <tr>
                                                                <th className="px-6 py-3 text-left text-xs font-semibold text-gray-600 uppercase">Type</th>
                                                                <th className="px-6 py-3 text-left text-xs font-semibold text-gray-600 uppercase">User</th>
                                                                <th className="px-6 py-3 text-left text-xs font-semibold text-gray-600 uppercase">Action</th>
                                                                <th className="px-6 py-3 text-left text-xs font-semibold text-gray-600 uppercase">Description</th>
                                                                <th className="px-6 py-3 text-left text-xs font-semibold text-gray-600 uppercase">IP Address</th>
                                                                <th className="px-6 py-3 text-left text-xs font-semibold text-gray-600 uppercase">Timestamp</th>
                                                            </tr>
                                                        </thead>
                                                        <tbody className="divide-y divide-gray-200">
                                                            {logs
                                                                .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
                                                                .map((log, index) => {
                                                                    const LogTypeIcon = getTypeIcon(log.type);
                                                                    return (
                                                                        <tr
                                                                            key={`${log.id}-${index}`}
                                                                            className={`hover:bg-red-50 transition-colors ${
                                                                                index % 2 === 0 ? 'bg-white' : 'bg-gray-50'
                                                                            }`}
                                                                        >
                                                                            <td className="px-6 py-4">
                                                                                <div className="flex items-center gap-2">
                                                                                    <div className="p-2 bg-blue-100 rounded-full">
                                                                                        <LogTypeIcon className="w-4 h-4 text-blue-600" />
                                                                                    </div>
                                                                                    <span className="text-sm font-medium text-gray-900">{log.type}</span>
                                                                                </div>
                                                                            </td>
                                                                            <td className="px-6 py-4">
                                                                                <div className="flex items-center gap-2">
                                                                                    <User className="w-4 h-4 text-gray-400" />
                                                                                    <span className="text-sm text-gray-900">{log.user_name || 'N/A'}</span>
                                                                                </div>
                                                                            </td>
                                                                            <td className="px-6 py-4">
                                                                                <span className={`inline-flex items-center px-2 py-1 rounded-md text-xs font-medium ${getActionBadgeColor(log.action)}`}>
                                                                                    {log.action || 'N/A'}
                                                                                </span>
                                                                            </td>
                                                                            <td className="px-6 py-4">
                                                                                <span className="text-sm text-gray-700">{log.description || 'N/A'}</span>
                                                                            </td>
                                                                            <td className="px-6 py-4">
                                                                                <span className="text-sm text-gray-600 font-mono">{log.ip_address || 'N/A'}</span>
                                                                            </td>
                                                                            <td className="px-6 py-4">
                                                                                <div className="flex items-center gap-2">
                                                                                    <Clock className="w-4 h-4 text-gray-400" />
                                                                                    <span className="text-sm text-gray-600">{formatDateTime(log.timestamp)}</span>
                                                                                </div>
                                                                            </td>
                                                                        </tr>
                                                                    );
                                                                })}
                                                        </tbody>
                                                    </table>
                                                </div>
                                            )}
                                        </div>
                                    );
                                })
                        )}
                    </div>
                </div>
            </div>
        </AuthenticatedLayout>
    );
}

export default AuditTrails;
