// Your imports remain the same
import ApplicationLogo from '@/Components/ApplicationLogo';
import Dropdown from '@/Components/Dropdown';
import NavLink from '@/Components/NavLink';
import ResponsiveNavLink from '@/Components/ResponsiveNavLink';
import { Link, usePage } from '@inertiajs/react';
import { PropsWithChildren, ReactNode, useState } from 'react';

// Define the User type with a role property
interface User {
    id: number;
    name: string;
    email: string;
    role: number; 
}

export default function Authenticated({
    header,
    children,
}: PropsWithChildren<{ header?: ReactNode }>) {
    const { auth } = usePage().props;
    const user: User = auth.user;
    const [sidebarOpen, setSidebarOpen] = useState(false);

    return (
        <div className="flex min-h-screen bg-gray-100 relative">

          
            {/* Sidebar */}
            <aside
                className={`${
                    sidebarOpen ? 'w-64' : 'w-0'
                } bg-white transition-all duration-300 overflow-hidden shadow-md pt-16 z-10 fixed top-0 left-0 h-full flex flex-col`}
            >
                <div className="border-t border-gray-200 pt-4 px-4 flex-1">
                    <div className="mt-3 space-y-1">
                        {/* <button
                            onClick={() => window.location.href = '/createquiz'}
                            className="bg-red-600 text-white px-6 py-3 rounded-md w-full shadow-lg text-lg font-semibold"
                        >
                            Create
                        </button> */}
                    </div>

                    {/* Links section */}
                    <div className="mt-6 space-y-4">
                        {/* Check user role and render menu accordingly */}
                        {user?.role === 2 ? (
                            <>
                               <ResponsiveNavLink href="dashboard" className="text-red-600">
                                    Dashboard
                                </ResponsiveNavLink>
                                <ResponsiveNavLink href="explore" className="text-red-600">
                                    Explore
                                </ResponsiveNavLink>
                                <ResponsiveNavLink href="myquizzes" className="text-red-600">
                                    My Quizzes
                                </ResponsiveNavLink>
                                <ResponsiveNavLink href="myperformance" className="text-red-600">
                                    My Performance
                                </ResponsiveNavLink>
                            </>
                        ) : (user?.role === 3 || user?.role === 1) ? (
                            // Organizer and Teacher Menu
                            <>
                                <ResponsiveNavLink href={user?.role === 3 ? "/organizerLobby" : "/dashboard"} className="text-red-600">
                                    Dashboard
                                </ResponsiveNavLink>
                                <ResponsiveNavLink href="/audit-trails" className="text-red-600">
                                    All Audit Trails
                                </ResponsiveNavLink>
                                <ResponsiveNavLink href="/session-history" className="text-red-600">
                                    Session History
                                </ResponsiveNavLink>
                                {user?.role === 3 && (
                                    <ResponsiveNavLink href="/lobby-management" className="text-red-600">
                                        Lobby Management
                                    </ResponsiveNavLink>
                                )}
                                <ResponsiveNavLink href="/quiz-management" className="text-red-600">
                                    Quiz Management
                                </ResponsiveNavLink>
                                <ResponsiveNavLink href="/scoring" className="text-red-600">
                                    Scoring / Results
                                </ResponsiveNavLink>
                                <ResponsiveNavLink href="/statistics" className="text-red-600">
                                    Question Statistics
                                </ResponsiveNavLink>
                                {user?.role === 3 && (
                                    <ResponsiveNavLink href="/pre-registration" className="text-red-600">
                                        Pre-Registration Logs
                                    </ResponsiveNavLink>
                                )}
                            </>
                        ) : (
                            // Other roles
                            <>
                               <ResponsiveNavLink href="dashboard" className="text-red-600">
                                    Dashboard
                                </ResponsiveNavLink>
                                <ResponsiveNavLink href="explore" className="text-red-600">
                                    Explore
                                </ResponsiveNavLink>
                                <ResponsiveNavLink href="mylibrary" className="text-red-600">
                                    Library
                                </ResponsiveNavLink>
                                <ResponsiveNavLink href="templates" className="text-red-600">
                                    Templates 
                                </ResponsiveNavLink>
                            </>
                        )}
                    </div>
                </div>

                {/* Footer image */}
                <div className="px-0 pb-0 flex justify-center w-full h-full">
                    <img
                        src="/images/footer.png"
                        alt="Sidebar Image"
                        className="w-full h-full object-cover rounded-none"
                    />
                </div>
            </aside>

            {/* Main content wrapper */}
            <div className="flex-1 flex flex-col" style={{ marginLeft: sidebarOpen ? '16rem' : '0' }}>
                {/* Top navbar */}
                <div className="fixed top-0 left-0 right-0 h-16 px-4 bg-yellow-200 shadow z-30 flex items-center justify-between">
                    <button
                        onClick={() => setSidebarOpen(!sidebarOpen)}
                        className="focus:outline-none"
                    >
                        <img
                            src="/images/carousel/logooo.png"
                            alt="Menu"
                            className="h-14 w-14"
                        />
                    </button>

                    <div className="hidden sm:flex items-center">
                        <Dropdown>
                            <Dropdown.Trigger>
                                <span className="inline-flex rounded-md">
                                    <button
                                        type="button"
                                        className="inline-flex items-center rounded-md border border-transparent bg-white px-3 py-2 text-sm font-medium leading-4 text-gray-500 transition duration-150 ease-in-out hover:text-gray-700 focus:outline-none"
                                    >
                                        <svg
                                            className="h-6 w-6 text-gray-500"
                                            xmlns="http://www.w3.org/2000/svg"
                                            viewBox="0 0 20 20"
                                            fill="currentColor"
                                        >
                                            <path
                                                fillRule="evenodd"
                                                d="M10 0a5 5 0 11-5 5 5 5 0 015-5zm0 6a3 3 0 100 6 3 3 0 000-6zm0 8c-1.5 0-4 1.2-4 3v2h8v-2c0-1.8-2.5-3-4-3z"
                                                clipRule="evenodd"
                                            />
                                        </svg>
                                    </button>
                                </span>
                            </Dropdown.Trigger>

                            <Dropdown.Content>
                                <Dropdown.Link href={route('profile.edit')}>
                                    Profile
                                </Dropdown.Link>
                                <Dropdown.Link href={route('settings')}>
                                    Settings
                                </Dropdown.Link>
                                {/* Hide logout for participants (role 4) */}
                                {user?.role !== 4 && (
                                    <Dropdown.Link
                                        href={route('logout')}
                                        method="post"
                                        as="button"
                                    >
                                        Log Out
                                    </Dropdown.Link>
                                )}
                            </Dropdown.Content>
                        </Dropdown>
                    </div>
                </div>

                {/* Header (optional) */}
                {header && (
                    <header className="bg-yellow-200 shadow mt-16">
                        <div className="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
                            {header}
                        </div>
                    </header>
                )}

                {/* Main content */}
                <main className="flex-1 p-4 mt-16">{children}</main>
            </div>
        </div>
    );
}
