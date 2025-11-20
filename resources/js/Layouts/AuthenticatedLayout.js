import { jsx as _jsx, Fragment as _Fragment, jsxs as _jsxs } from "react/jsx-runtime";
import Dropdown from '@/Components/Dropdown';
import ResponsiveNavLink from '@/Components/ResponsiveNavLink';
import { usePage } from '@inertiajs/react';
import { useState } from 'react';
export default function Authenticated({ header, children, }) {
    const { auth } = usePage().props;
    const user = auth.user;
    const [sidebarOpen, setSidebarOpen] = useState(false);
    // return (
    //     _jsxs("div", { className: "flex min-h-screen bg-gray-100 relative", children: [_jsxs("aside", { className: `${sidebarOpen ? 'w-64' : 'w-0'} bg-white transition-all duration-300 overflow-hidden shadow-md pt-16 z-10 fixed top-0 left-0 h-full flex flex-col`, children: [_jsxs("div", { className: "border-t border-gray-200 pt-4 px-4 flex-1", children: [_jsx("div", { className: "mt-3 space-y-1", children: _jsx("button", { onClick: () => window.location.href = '/createquiz', className: "bg-red-600 text-white px-6 py-3 rounded-md w-full shadow-lg text-lg font-semibold", children: "Create" }) }), _jsx("div", { className: "mt-6 space-y-1", children: user?.role === 2 ? (_jsxs(_Fragment, { children: [_jsx(ResponsiveNavLink, { href: "/dashboard", className: "text-red-600", children: "Dashboard" }), _jsx(ResponsiveNavLink, { href: "explore", className: "text-red-600", children: "Explore" }), _jsx(ResponsiveNavLink, { href: "myquizzes", className: "text-red-600", children: "My Quizzes" }), _jsx(ResponsiveNavLink, { href: "myperformance", className: "text-red-600", children: "My Performance" })] })) : (_jsxs(_Fragment, { children: [_jsx(ResponsiveNavLink, { href: "/dashboard", className: "text-red-600", children: "Dashboard" }), _jsx(ResponsiveNavLink, { href: "explore", className: "text-red-600", children: "Explore" }), _jsx(ResponsiveNavLink, { href: "mylibrary", className: "text-red-600", children: "Library" }), _jsx(ResponsiveNavLink, { href: "/templates", className: "text-red-600", children: "Templates" }), _jsx(ResponsiveNavLink, { href: "/statistics", className: "text-red-600", children: "Question Statistics" })] })) })] }), _jsx("div", { className: "px-0 pb-0 flex justify-center w-full h-full", children: _jsx("img", { src: "/images/footer.png", alt: "Sidebar Image", className: "w-full h-full object-cover rounded-none" }) })] }), _jsxs("div", { className: "flex-1 flex flex-col", style: { marginLeft: sidebarOpen ? '16rem' : '0' }, children: [_jsxs("div", { className: "fixed top-0 left-0 right-0 h-16 px-4 bg-yellow-200 shadow z-30 flex items-center justify-between", children: [_jsx("button", { onClick: () => setSidebarOpen(!sidebarOpen), className: "focus:outline-none", children: _jsx("img", { src: "/images/carousel/logooo.png", alt: "Menu", className: "h-14 w-14" }) }), _jsx("div", { className: "hidden sm:flex items-center", children: _jsxs(Dropdown, { children: [_jsx(Dropdown.Trigger, { children: _jsx("span", { className: "inline-flex rounded-md", children: _jsx("button", { type: "button", className: "inline-flex items-center rounded-md border border-transparent bg-white px-3 py-2 text-sm font-medium leading-4 text-gray-500 transition duration-150 ease-in-out hover:text-gray-700 focus:outline-none", children: _jsx("svg", { className: "h-6 w-6 text-gray-500", xmlns: "http://www.w3.org/2000/svg", viewBox: "0 0 20 20", fill: "currentColor", children: _jsx("path", { fillRule: "evenodd", d: "M10 0a5 5 0 11-5 5 5 5 0 015-5zm0 6a3 3 0 100 6 3 3 0 000-6zm0 8c-1.5 0-4 1.2-4 3v2h8v-2c0-1.8-2.5-3-4-3z", clipRule: "evenodd" }) }) }) }) }), _jsxs(Dropdown.Content, { children: [_jsx(Dropdown.Link, { href: route('profile.edit'), children: "Profile" }), _jsx(Dropdown.Link, { href: route('settings'), children: "Settings" }), _jsx(Dropdown.Link, { href: route('logout'), method: "post", as: "button", children: "Log Out" })] })] }) })] }), header && (_jsx("header", { className: "bg-yellow-200 shadow mt-16", children: _jsx("div", { className: "max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8", children: header }) })), _jsx("main", { className: "flex-1 p-4 mt-16", children: children })] })] })
    // );


    return (
  _jsxs("div", {
    className: "flex min-h-screen bg-gray-100 relative",
    children: [
      _jsxs("aside", {
        className: `${
          sidebarOpen ? "w-64" : "w-0"
        } bg-white transition-all duration-300 overflow-hidden shadow-md pt-16 z-10 fixed top-0 left-0 h-full flex flex-col`,
        children: [
          _jsxs("div", {
            className: "border-t border-gray-200 pt-4 px-4 flex-1",
            children: [
              _jsx("div", {
                className: "mt-3 space-y-1",
                children: _jsx("button", {
                  onClick: () => (window.location.href = "/createquiz"),
                  className:
                    "bg-red-600 text-white px-6 py-3 rounded-md w-full shadow-lg text-lg hidden font-semibold",
                  children: "Create",
                }),
              }),
              _jsx("div", {
                className: "mt-6 space-y-1",
                children:
                  user?.role === 2
                    ? _jsxs(_Fragment, {
                        children: [
                          _jsx(ResponsiveNavLink, {
                            href: "/dashboard",
                            className: "text-red-600",
                            children: "Dashboard",
                          }),
                          _jsx(ResponsiveNavLink, {
                            href: "explore",
                            className: "text-red-600",
                            children: "Session History",
                          }),
                          _jsx(ResponsiveNavLink, {
                            href: "myquizzes",
                            className: "text-red-600",
                            children: "My Quizzes",
                          }),
                          _jsx(ResponsiveNavLink, {
                            href: "myperformance",
                            className: "text-red-600",
                            children: "My Performance",
                          }),
                        ],
                      })
                    : (user?.role === 3 || user?.role === 1)
                    ? _jsxs(_Fragment, {
                        // Organizer and Teacher Menu
                        children: [
                          _jsx(ResponsiveNavLink, {
                            href: user?.role === 3 ? "/organizerLobby" : "/dashboard",
                            className: "text-red-600",
                            children: "Dashboard",
                          }),
                          _jsx(ResponsiveNavLink, {
                            href: "/audit-trails",
                            className: "text-red-600",
                            children: "All Audit Trails",
                          }),
                          _jsx(ResponsiveNavLink, {
                            href: "/session-history",
                            className: "text-red-600",
                            children: "Session History",
                          }),
                          user?.role === 3 && _jsx(ResponsiveNavLink, {
                            href: "/lobby-management",
                            className: "text-red-600",
                            children: "Lobby Management",
                          }),
                          _jsx(ResponsiveNavLink, {
                            href: "/quiz-management",
                            className: "text-red-600",
                            children: "Quiz Management",
                          }),
                          _jsx(ResponsiveNavLink, {
                            href: "/scoring",
                            className: "text-red-600",
                            children: "Scoring / Results",
                          }),
                          _jsx(ResponsiveNavLink, {
                            href: "/statistics",
                            className: "text-red-600",
                            children: "Question Statistics",
                          }),
                          user?.role === 3 && _jsx(ResponsiveNavLink, {
                            href: "/pre-registration",
                            className: "text-red-600",
                            children: "Pre-Registration Logs",
                          }),
                        ],
                      })
                    : _jsxs(_Fragment, {
                        // Other roles
                        children: [
                          _jsx(ResponsiveNavLink, {
                            href: "/dashboard",
                            className: "text-red-600",
                            children: "Dashboard",
                          }),
                          _jsx(ResponsiveNavLink, {
                            href: "explore",
                            className: "text-red-600",
                            children: "Explore",
                          }),
                          _jsx(ResponsiveNavLink, {
                            href: "mylibrary",
                            className: "text-red-600",
                            children: "Library",
                          }),
                          _jsx(ResponsiveNavLink, {
                            href: "/templates",
                            className: "text-red-600",
                            children: "Templates",
                          }),
                        ],
                      }),
              }),
            ],
          }),
          _jsx("div", {
            className: "px-0 pb-0 flex justify-center w-full h-full",
            children: _jsx("img", {
              src: "/images/footer.png",
              alt: "Sidebar Image",
              className: "w-full h-full object-cover rounded-none",
            }),
          }),
        ],
      }),

      _jsxs("div", {
        className: "flex-1 flex flex-col",
        style: { marginLeft: sidebarOpen ? "16rem" : "0" },
        children: [
          _jsxs("div", {
            className:
              "fixed top-0 left-0 right-0 h-16 px-4 bg-yellow-200 shadow z-30 flex items-center justify-between",
            children: [
              _jsx("button", {
                onClick: () =>  {!user ? {} :setSidebarOpen(!sidebarOpen) },
                className: "focus:outline-none",
                children: _jsx("img", {
                  src: "/images/carousel/logooo.png",
                  alt: "Menu",
                  className: "h-14 w-14",
                 
                }),
              }),
              _jsx("div", {
                className: "hidden sm:flex items-center",
                children: _jsxs(Dropdown, {
                  children: [
                    _jsx(Dropdown.Trigger, {
                      children: _jsx("span", {
                        className: "inline-flex rounded-md",
                        children: _jsx("button", {
                          type: "button",
                          className:
                            "inline-flex items-center rounded-md border border-transparent bg-white px-3 py-2 text-sm font-medium leading-4 text-gray-500 transition duration-150 ease-in-out hover:text-gray-700 focus:outline-none",
                          children: _jsx("svg", {
                            className: "h-6 w-6 text-gray-500",
                            xmlns: "http://www.w3.org/2000/svg",
                            viewBox: "0 0 20 20",
                            fill: "currentColor",
                            children: _jsx("path", {
                              fillRule: "evenodd",
                              d: "M10 0a5 5 0 11-5 5 5 5 0 015-5zm0 6a3 3 0 100 6 3 3 0 000-6zm0 8c-1.5 0-4 1.2-4 3v2h8v-2c0-1.8-2.5-3-4-3z",
                              clipRule: "evenodd",
                            }),
                          }),
                        }),
                      }),
                    }),
                    auth?.user &&
                    _jsxs(Dropdown.Content, {
                      children: [
                        _jsx(Dropdown.Link, {
                          href: route("profile.edit"),
                          children: "Profile",
                        }),
                        _jsx(Dropdown.Link, {
                          href: route("settings"),
                          children: "Settings",
                        }),
                        user?.role !== 4 &&
                        _jsx(Dropdown.Link, {
                          href: route("logout"),
                          method: "post",
                          as: "button",
                          children: "Log Out",
                        }),
                      ],
                    }),
                  ],
                }),
              }),
            ],
          }),

          header &&
            _jsx("header", {
              className: "bg-yellow-200 shadow mt-16",
              children: _jsx("div", {
                className: "max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8",
                children: header,
              }),
            }),

          _jsx("main", {
            className: "flex-1 p-4 mt-16",
            children: children,
          }),
        ],
      }),
    ],
  })
);
}