import React, { useEffect, useState } from 'react';
import { Head, router, useForm, usePage } from '@inertiajs/react';
import { Button } from '@/Components/ui/button';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/Components/ui/card';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/Components/ui/dialog';
import { Input } from '@/Components/ui/input';
import { Label } from '@/Components/ui/label';
import axios from 'axios';
import AuthenticatedLayout from '@/Layouts/AuthenticatedLayout';
import Swal from 'sweetalert2';
import { Calendar } from '@/Components/ui/calendar';
import { Clock } from 'lucide-react';

// Countdown Timer Component
const CountdownTimer = ({ startDate }: { startDate: string | Date }) => {
    const [timeLeft, setTimeLeft] = useState({
        days: 0,
        hours: 0,
        minutes: 0,
        seconds: 0
    });
    const [expired, setExpired] = useState(false);

    useEffect(() => {
        if (!startDate) return;

        const updateCountdown = () => {
            const now = new Date().getTime();
            // Parse the date - handle both string and Date object
            const start = startDate instanceof Date ? startDate.getTime() : new Date(startDate).getTime();
            const difference = start - now;

            if (difference <= 0) {
                setExpired(true);
                setTimeLeft({ days: 0, hours: 0, minutes: 0, seconds: 0 });
                return;
            }

            const days = Math.floor(difference / (1000 * 60 * 60 * 24));
            const hours = Math.floor((difference % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
            const minutes = Math.floor((difference % (1000 * 60 * 60)) / (1000 * 60));
            const seconds = Math.floor((difference % (1000 * 60)) / 1000);

            setTimeLeft({ days, hours, minutes, seconds });
        };

        // Update immediately
        updateCountdown();

        // Update every second
        const interval = setInterval(updateCountdown, 1000);

        return () => clearInterval(interval);
    }, [startDate]);

    if (expired || !startDate) return null;

    const now = new Date().getTime();
    const start = startDate instanceof Date ? startDate.getTime() : new Date(startDate).getTime();
    if (start <= now) return null;

    return (
        <div className="bg-gradient-to-r from-orange-50 to-red-50 rounded-lg p-3 border border-orange-200">
            <div className="flex items-center gap-2 mb-2">
                <Clock className="w-4 h-4 text-orange-600" />
                <p className="text-xs font-semibold text-orange-700">Starts in:</p>
            </div>
            <div className="flex gap-2">
                {timeLeft.days > 0 && (
                    <div className="text-center">
                        <div className="text-lg font-bold text-orange-700">{timeLeft.days}</div>
                        <div className="text-xs text-orange-600">d</div>
                    </div>
                )}
                <div className="text-center">
                    <div className="text-lg font-bold text-orange-700">{String(timeLeft.hours).padStart(2, '0')}</div>
                    <div className="text-xs text-orange-600">h</div>
                </div>
                <div className="text-center">
                    <div className="text-lg font-bold text-orange-700">{String(timeLeft.minutes).padStart(2, '0')}</div>
                    <div className="text-xs text-orange-600">m</div>
                </div>
                <div className="text-center">
                    <div className="text-lg font-bold text-orange-700">{String(timeLeft.seconds).padStart(2, '0')}</div>
                    <div className="text-xs text-orange-600">s</div>
                </div>
            </div>
        </div>
    );
};

type Props = {}

const OrganizerLobby = (props: Props) => {
    const { lobby } = usePage().props;
    const { data, setData, post, processing, errors, reset, transform } = useForm({
        name: '',
        code: '',
        date: new Date()
    });
    const [time, setTime] = useState<string>('12:00');
    
    const buildDateTimePayload = (baseDate: Date | string, timeValue: string) => {
        const sourceDate = baseDate instanceof Date ? new Date(baseDate.getTime()) : new Date(baseDate);

        if (Number.isNaN(sourceDate.getTime())) {
            return '';
        }

        const [hours = '0', minutes = '0'] = timeValue?.split(':') ?? [];
        const parsedHours = Number.parseInt(hours, 10);
        const parsedMinutes = Number.parseInt(minutes, 10);

        sourceDate.setHours(Number.isNaN(parsedHours) ? 0 : parsedHours);
        sourceDate.setMinutes(Number.isNaN(parsedMinutes) ? 0 : parsedMinutes);
        sourceDate.setSeconds(0, 0);

        const pad = (value: number) => value.toString().padStart(2, '0');

        return `${sourceDate.getFullYear()}-${pad(sourceDate.getMonth() + 1)}-${pad(sourceDate.getDate())} ${pad(sourceDate.getHours())}:${pad(sourceDate.getMinutes())}:${pad(sourceDate.getSeconds())}`;
    };
    
    // Transform date and time before sending to backend
    transform((data) => {
        const formattedDate = buildDateTimePayload(data.date, time);
        
        return {
            ...data,
            date: formattedDate || buildDateTimePayload(new Date(), time),
        };
    });

    const [editingLobby, setEditingLobby] = useState<any>(null);
    const [editDialogOpen, setEditDialogOpen] = useState(false);
    const { data: editData, setData: setEditData, post: editPost, processing: editProcessing, errors: editErrors, reset: resetEdit } = useForm({
        name: '',
        code: ''
    });
    const [availableLobbies, setAvailableLobbies] = useState<any>([]);
    const [addLobby, setAddLobby] = useState(false)

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        post(route('lobby.store'), {
            onSuccess: () => {
                setData('code', '')
                setData('name', '')
                setData('date', new Date())
                setTime('12:00')
                // Close dialog after successful submission
                const dialogClose = document.querySelector('[data-dialog-close]') as HTMLButtonElement;
                if (dialogClose) dialogClose.click();
                Swal.fire({
                    toast: true,
                    position: 'top-end',
                    icon: 'success',
                    title: 'Lobby Created Successfully',
                    showConfirmButton: false,
                    timer: 3000,
                    timerProgressBar: true,
                    background: '#fff',
                    color: '#399918',
                    iconColor: '#399918 ',
                });
            },
            onError: (errors) => {
                // Error handling is already done by Inertia's error bag
                // The errors.code will be displayed in the form
                if (errors.code) {
                    Swal.fire({
                        toast: true,
                        position: 'top-end',
                        icon: 'error',
                        title: 'Lobby Code Already Exists',
                        text: errors.code,
                        showConfirmButton: false,
                        timer: 4000,
                        timerProgressBar: true,
                    });
                }
            }
        });
    };
    const handleEditSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        if (!editingLobby) return;


        editPost(route('lobby.update', editingLobby.id), {
            onSuccess: () => {
                setEditDialogOpen(false);
                setEditingLobby(null);
                resetEdit();
                getLobbies(); // Refresh the lobbies list
                Swal.fire({
                    toast: true,
                    position: 'top-end',
                    icon: 'success',
                    title: 'Lobby Updated',
                    showConfirmButton: false,
                    timer: 3000,
                    timerProgressBar: true,
                    background: '#fff',
                    color: '#399918',
                    iconColor: '#399918 ',
                });
            }
        });
    };
    const handleDelete = (id: string) => {
        Swal.fire({
            title: 'Are you sure?',
            text: "This action cannot be undone!",
            icon: 'warning',
            showCancelButton: true,
            confirmButtonColor: '#d33',
            cancelButtonColor: '#3085d6',
            confirmButtonText: 'Yes, delete it!',
            cancelButtonText: 'Cancel'
        }).then((result) => {
            if (result.isConfirmed) {
                router.post(`/lobby/${id}/delete`, {}, {
                    onSuccess: () => {
                        Swal.fire({
                            toast: true,
                            position: 'top-end',
                            icon: 'success',
                            title: 'Lobby Deleted',
                            showConfirmButton: false,
                            timer: 3000,
                            timerProgressBar: true,
                            background: '#fff',
                            color: '#399918',
                            iconColor: '#399918',
                        });
                    }
                });
            }
        });
    };
    const handleEditClick = (lobby: any) => {
        setEditingLobby(lobby);
        setEditData('name', lobby.name);
        setEditData('code', lobby.lobby_code);
        setEditDialogOpen(true);
    };

    const getLobbies = async () => {
        try {
            const response = await axios.get("/organizer-lobbies")

            console.log("ress", response)

            setAvailableLobbies(response.data)
        } catch (error) {
            console.log(error)
        }
    }

    const handleClickCategory = (code: string) => {

        router.get(`lobbyCategory/${code}`)
    }
    useEffect(() => {
        getLobbies()
    }, [])

    useEffect(() => {
        setAvailableLobbies(lobby)
    }, [lobby])

    return (
        <AuthenticatedLayout>
            <Head title="Event Rooms" />
            <div className="min-h-screen bg-gradient-to-br from-red-50 to-red-100 flex flex-col p-6">


                <div className='bg-white/80 backdrop-blur-sm grid rounded-xl shadow-lg p-6 gap-6'>


                    <div className='col-span-5 space-y-6'>
                        <h1 className="text-3xl font-bold text-red-800 tracking-tight">Event Rooms</h1>
                        <div className="flex justify-end">
                            {/* <Dialog>
                            <DialogTrigger asChild>
                                <Button className="bg-gradient-to-r from-red-500 to-red-600 hover:from-red-600 hover:to-red-700 text-white font-semibold rounded-xl px-6 py-2 shadow-md hover:shadow-lg transition-all duration-300">
                                    Add Lobby +
                                </Button>
                            </DialogTrigger>
                            <DialogContent className="sm:max-w-[425px] bg-white">
                                <DialogHeader>
                                    <DialogTitle className="text-2xl font-semibold text-red-700">Create New Lobby</DialogTitle>
                                    <DialogDescription className="text-red-600/80">
                                        Fill in the details below to create a new lobby.
                                    </DialogDescription>
                                </DialogHeader>
                                <form onSubmit={handleSubmit} className="space-y-4 mt-4">
                                    <div className="space-y-2">
                                        <Label htmlFor="name" className="text-sm font-medium text-red-700">Lobby Name</Label>
                                        <Input
                                            id="name"
                                            placeholder="Enter lobby name"
                                            className="border-red-200 focus:border-red-500 focus:ring-red-500"
                                            value={data.name}
                                            onChange={e => setData('name', e.target.value)}
                                        />
                                        {errors.name && <p className="text-red-500 text-sm mt-1">{errors.name}</p>}
                                    </div>
                                    <div className="space-y-2">
                                        <Label htmlFor="code" className="text-sm font-medium text-red-700">Lobby Code</Label>
                                        <Input
                                            id="code"
                                            placeholder="Enter lobby code"
                                            className="border-red-200 focus:border-red-500 focus:ring-red-500"
                                            value={data.code}
                                            onChange={e => setData('code', e.target.value)}
                                        />
                                        {errors.code && <p className="text-red-500 text-sm mt-1">{errors.code}</p>}
                                    </div>
                                    <DialogFooter className="mt-6">
                                        <Button
                                            type="submit"
                                            className="w-full bg-gradient-to-r from-red-500 to-red-600 hover:from-red-600 hover:to-red-700 text-white font-semibold rounded-xl px-6 py-2 shadow-md hover:shadow-lg transition-all duration-300"
                                        >
                                            {processing ? 'Creating...' : 'Create Lobby'}
                                        </Button>
                                    </DialogFooter>
                                </form>
                            </DialogContent>
                        </Dialog> */}
                            {/* Only show Add Lobby button when there are existing lobbies */}
                            {availableLobbies && availableLobbies.length > 0 && (
                                <div className="flex justify-end">
                                    <Dialog>
                                        <DialogTrigger asChild>
                                            <Button className="bg-gradient-to-r from-red-500 to-red-600 hover:from-red-600 hover:to-red-700 text-white font-semibold rounded-xl px-6 py-2 shadow-md hover:shadow-lg transition-all duration-300">
                                                Add Lobby +
                                            </Button>
                                        </DialogTrigger>
                                        <DialogContent className="sm:max-w-[425px] bg-white">
                                            <DialogHeader>
                                                <DialogTitle className="text-2xl font-semibold text-red-700">Create New Lobby</DialogTitle>
                                                <DialogDescription className="text-red-600/80">
                                                    Fill in the details below to create a new lobby.
                                                </DialogDescription>
                                            </DialogHeader>
                                            <form onSubmit={handleSubmit} className="space-y-4 mt-4">
                                                <div className="space-y-2">
                                                    <Label htmlFor="name" className="text-sm font-medium text-red-700">Lobby Name</Label>
                                                    <Input
                                                        id="name"
                                                        placeholder="Enter lobby name"
                                                        className="border-red-200 focus:border-red-500 focus:ring-red-500"
                                                        value={data.name}
                                                        onChange={e => setData('name', e.target.value)}
                                                        required
                                                    />
                                                    {errors.name && <p className="text-red-500 text-sm mt-1">{errors.name}</p>}
                                                </div>
                                                <div className="space-y-2">
                                                    <Label htmlFor="code" className="text-sm font-medium text-red-700">Lobby Code</Label>
                                                    <Input
                                                        id="code"
                                                        placeholder="Enter lobby code"
                                                        className="border-red-200 focus:border-red-500 focus:ring-red-500"
                                                        value={data.code}
                                                        onChange={e => setData('code', e.target.value)}
                                                        required
                                                    />
                                                    {errors.code && <p className="text-red-500 text-sm mt-1">{errors.code}</p>}
                                                </div>
                                                <div className="space-y-4">
                                                    <div>
                                                        <Label className="text-sm font-medium text-red-700"> Select Start Date </Label>
                                                        <Calendar
                                                            mode="single"
                                                            selected={data.date}
                                                            onSelect={(e) => setData("date", new Date(e))}
                                                            className="rounded-md border shadow-sm text-lg w-full"
                                                            captionLayout="dropdown"
                                                        />
                                                    </div>
                                                    <div className="space-y-2">
                                                        <Label htmlFor="time" className="text-sm font-medium text-red-700">Select Start Time</Label>
                                                        <Input
                                                            id="time"
                                                            type="time"
                                                            className="border-red-200 focus:border-red-500 focus:ring-red-500"
                                                            value={time}
                                                            onChange={e => setTime(e.target.value)}
                                                            required
                                                        />
                                                    </div>
                                                </div>
                                                <DialogFooter className="mt-6">
                                                    <Button
                                                        type="submit"
                                                        className="w-full bg-gradient-to-r from-red-500 to-red-600 hover:from-red-600 hover:to-red-700 text-white font-semibold rounded-xl px-6 py-2 shadow-md hover:shadow-lg transition-all duration-300"
                                                    >
                                                        {processing ? 'Creating...' : 'Create Lobby'}
                                                    </Button>
                                                </DialogFooter>
                                            </form>
                                        </DialogContent>
                                    </Dialog>
                                </div>
                            )}

                        </div>
                        <div className="space-y-4">
                            {addLobby ? (
                                <Card className="bg-white/90 backdrop-blur-sm shadow-lg hover:shadow-xl transition-all duration-300 rounded-xl border border-red-200">
                                    <CardHeader>
                                        <CardTitle className='text-2xl text-red-600 font-bold tracking-tight'>Add Event</CardTitle>
                                    </CardHeader>
                                    <CardContent>
                                        <div className="flex flex-col justify-start text-left gap-y-3">
                                            <label className="font-semibold text-red-700">Event Name</label>
                                            <input
                                                type="text"
                                                className="w-full p-3 border border-red-200 rounded-xl mb-4 text-red-800 focus:ring-2 focus:ring-red-500 focus:border-transparent transition-all duration-200"
                                                required
                                            />
                                        </div>
                                    </CardContent>
                                    <CardFooter>
                                        <Button className="bg-gradient-to-r from-red-500 to-red-600 hover:from-red-600 hover:to-red-700 text-white font-semibold rounded-xl px-6 py-2 shadow-md hover:shadow-lg transition-all duration-300">
                                            Create
                                        </Button>
                                    </CardFooter>
                                </Card>
                            ) : availableLobbies && availableLobbies.length > 0 ? (
                                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
                                    {availableLobbies.map((al) => (
                                        <Card
                                            key={al.lobby_code}
                                            className="bg-white/95 backdrop-blur-sm rounded-xl shadow-lg hover:shadow-xl border border-red-200 transform hover:scale-[1.02] transition-all duration-300 overflow-hidden"
                                        >
                                            <CardHeader className="pb-3">
                                                <div className="flex justify-between items-start">
                                                    <CardTitle className="text-xl uppercase font-bold text-red-800 truncate pr-2">
                                                        {al.name}
                                                    </CardTitle>
                                                    <div className="flex space-x-1 flex-shrink-0">
                                                        {/* Pre-Registration Button */}
                                                        <button
                                                            onClick={(e) => {
                                                                e.stopPropagation();
                                                                router.get(`/manage-pre-registration/${al.lobby_code}`)
                                                                // Add pre-registration functionality
                                                                // handlePreRegistration(al.id);
                                                            }}
                                                            className="p-2 rounded-lg bg-green-100 hover:bg-green-200 text-green-600 transition-colors duration-200"
                                                            title="Pre-registration"
                                                        >
                                                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18 9v3m0 0v3m0-3h3m-3 0h-3m-2-5a4 4 0 11-8 0 4 4 0 018 0zM3 20a6 6 0 0112 0v1H3v-1z" />
                                                            </svg>
                                                        </button>

                                                        {/* Copy Code Button */}
                                                        <button
                                                            onClick={(e) => {
                                                                e.stopPropagation();
                                                                navigator.clipboard.writeText(al.lobby_code);
                                                                Swal.fire({
                                                                    toast: true,
                                                                    position: 'top-end',
                                                                    icon: 'success',
                                                                    title: 'Copied to clipboard',
                                                                    showConfirmButton: false,
                                                                    timer: 3000,
                                                                    timerProgressBar: true,
                                                                    background: '#fff',
                                                                    color: '#399918',
                                                                    iconColor: '#399918 ',
                                                                });
                                                                // You can add toast notification here
                                                            }}
                                                            className="p-2 rounded-lg bg-red-100 hover:bg-red-200 text-red-600 transition-colors duration-200"
                                                            title="Copy lobby code"
                                                        >
                                                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                                                            </svg>
                                                        </button>

                                                        {/* Edit Button */}
                                                        <button
                                                            onClick={(e) => {
                                                                e.stopPropagation();
                                                                // Add edit functionality
                                                                handleEditClick(al)
                                                            }}
                                                            className="p-2 rounded-lg bg-blue-100 hover:bg-blue-200 text-blue-600 transition-colors duration-200"
                                                            title="Edit lobby"
                                                        >
                                                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                                                            </svg>
                                                        </button>

                                                        {/* Delete Button */}
                                                        <button
                                                            onClick={(e) => {
                                                                e.stopPropagation();
                                                                // Add delete functionality

                                                                handleDelete(al.id)

                                                            }}
                                                            className="p-2 rounded-lg bg-red-100 hover:bg-red-200 text-red-600 transition-colors duration-200"
                                                            title="Delete lobby"
                                                        >
                                                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                                                            </svg>
                                                        </button>
                                                    </div>
                                                </div>
                                            </CardHeader>

                                            <CardContent
                                                className="space-y-4 cursor-pointer pb-4"
                                                onClick={() => handleClickCategory(al.lobby_code)}
                                            >
                                                {/* Lobby Code */}
                                                <div className="flex justify-between items-center">
                                                    <div>
                                                        <p className="text-sm text-red-500 font-medium">Lobby Code </p>
                                                        <p className="text-lg font-bold text-red-700 font-mono tracking-wide">{al.lobby_code}</p>
                                                    </div>
                                                    <div className="bg-red-100 px-3 py-1 rounded-full">
                                                        <span className="text-xs font-semibold text-red-600">ACTIVE</span>
                                                    </div>
                                                </div>

                                                {/* Scheduled Date */}
                                                <div>
                                                    <p className="text-sm text-gray-500 font-medium">
                                                        {al.start_date ? 'Scheduled' : 'Created'}
                                                    </p>
                                                    <p className="text-sm font-semibold text-gray-700">
                                                        {al.start_date ? (() => {
                                                            // Parse the date string - backend sends in 'Y-m-d H:i:s' format
                                                            // Treat it as local time (the time the user selected)
                                                            const dateStr = al.start_date;
                                                            let date: Date;
                                                            
                                                            if (dateStr instanceof Date) {
                                                                date = dateStr;
                                                            } else {
                                                                // Parse the date string - if it's in 'Y-m-d H:i:s' format, 
                                                                // JavaScript will parse it as local time
                                                                date = new Date(dateStr.replace(' ', 'T'));
                                                            }
                                                            
                                                            // Format the date in a readable format
                                                            return date.toLocaleDateString('en-US', {
                                                                year: 'numeric',
                                                                month: 'short',
                                                                day: 'numeric',
                                                                hour: '2-digit',
                                                                minute: '2-digit',
                                                                hour12: true
                                                            });
                                                        })() : (al.created_at ? (() => {
                                                            const date = al.created_at instanceof Date ? al.created_at : new Date(al.created_at);
                                                            return date.toLocaleDateString('en-US', {
                                                                year: 'numeric',
                                                                month: 'short',
                                                                day: 'numeric',
                                                                hour: '2-digit',
                                                                minute: '2-digit',
                                                                hour12: true
                                                            });
                                                        })() : 'Just now')}
                                                    </p>
                                                </div>

                                                {/* Countdown Timer */}
                                                {al.start_date && (() => {
                                                    // Parse the date and check if it's in the future
                                                    const dateStr = al.start_date;
                                                    const startDate = dateStr instanceof Date ? dateStr : new Date(dateStr);
                                                    const now = new Date();
                                                    return startDate.getTime() > now.getTime();
                                                })() && (
                                                    <CountdownTimer startDate={al.start_date} />
                                                )}

                                                {/* Participants */}
                                                {/* <div className="flex items-center justify-between pt-2 border-t border-gray-100">
                                                    <div className="flex items-center space-x-2">
                                                        <svg className="w-5 h-5 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m13.5-9a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0z" />
                                                        </svg>
                                                        <div>
                                                            <p className="text-sm text-gray-500">Participants</p>
                                                            <p className="text-lg font-bold text-red-600">
                                                                {al.participants_count || 0}
                                                            </p>
                                                        </div>
                                                    </div>
                                                    
                                           
                                                    <Button
                                                        onClick={(e) => {
                                                            e.stopPropagation();
                                                            handleClickCategory(al.lobby_code);
                                                        }}
                                                        className="bg-gradient-to-r from-red-500 to-red-600 hover:from-red-600 hover:to-red-700 text-white font-semibold rounded-lg px-4 py-2 text-sm shadow-md hover:shadow-lg transition-all duration-300"
                                                    >
                                                        Enter
                                                        <svg className="w-4 h-4 ml-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5m0 0l-5 5m5-5H6" />
                                                        </svg>
                                                    </Button>
                                                </div> */}
                                            </CardContent>
                                        </Card>
                                    ))}
                                </div>
                            ) : (
                                <div className="flex flex-col items-center justify-center py-16 px-6 text-center">
                                    <div className="mb-8">
                                        <svg className="w-32 h-32 mx-auto text-red-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" />
                                        </svg>
                                    </div>

                                    <h3 className="text-2xl font-bold text-red-800 mb-4">
                                        No Event Rooms Yet
                                    </h3>

                                    <p className="text-red-600 mb-8 max-w-md leading-relaxed">
                                        You haven't created any event rooms yet. Get started by creating your first lobby where participants can join and engage with your events.
                                    </p>

                                    <div className="space-y-4">
                                        <Dialog>
                                            <DialogTrigger asChild>
                                                <Button className="bg-gradient-to-r from-red-500 to-red-600 hover:from-red-600 hover:to-red-700 text-white font-semibold rounded-xl px-8 py-3 shadow-lg hover:shadow-xl transition-all duration-300 transform hover:scale-[1.02]">
                                                    <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
                                                    </svg>
                                                    Create Your First Event Room
                                                </Button>
                                            </DialogTrigger>
                                            <DialogContent className="sm:max-w-[425px] bg-white">
                                                <DialogHeader>
                                                    <DialogTitle className="text-2xl font-semibold text-red-700">Create New Lobby</DialogTitle>
                                                    <DialogDescription className="text-red-600/80">
                                                        Fill in the details below to create a new lobby.
                                                    </DialogDescription>
                                                </DialogHeader>
                                                <form onSubmit={handleSubmit} className="space-y-4 mt-4">
                                                    <div className="space-y-2">
                                                        <Label htmlFor="name" className="text-sm font-medium text-red-700">Lobby Name</Label>
                                                        <Input
                                                            id="name"
                                                            placeholder="Enter lobby name"
                                                            className="border-red-200 focus:border-red-500 focus:ring-red-500"
                                                            value={data.name}
                                                            onChange={e => setData('name', e.target.value)}
                                                            required
                                                        />
                                                        {errors.name && <p className="text-red-500 text-sm mt-1">{errors.name}</p>}
                                                    </div>
                                                    <div className="space-y-2">
                                                        <Label htmlFor="code" className="text-sm font-medium text-red-700">Lobby Code</Label>
                                                        <Input
                                                            id="code"
                                                            placeholder="Enter lobby code"
                                                            className="border-red-200 focus:border-red-500 focus:ring-red-500"
                                                            value={data.code}
                                                            onChange={e => setData('code', e.target.value)}
                                                        />
                                                        {errors.code && <p className="text-red-500 text-sm mt-1">{errors.code}</p>}
                                                    </div>
                                                    <div className="space-y-4">
                                                        <div>
                                                            <Label className="text-sm font-medium text-red-700"> Select Start Date </Label>
                                                            <Calendar
                                                                mode="single"
                                                                selected={data.date}
                                                                onSelect={(e) => setData("date", new Date(e))}
                                                                className="rounded-md border shadow-sm text-lg w-full"
                                                                captionLayout="dropdown"
                                                            />
                                                        </div>
                                                        <div className="space-y-2">
                                                            <Label htmlFor="time" className="text-sm font-medium text-red-700">Select Start Time</Label>
                                                            <Input
                                                                id="time"
                                                                type="time"
                                                                className="border-red-200 focus:border-red-500 focus:ring-red-500"
                                                                value={time}
                                                                onChange={e => setTime(e.target.value)}
                                                                required
                                                            />
                                                        </div>
                                                    </div>
                                                    <DialogFooter className="mt-6">
                                                        <Button
                                                            type="submit"
                                                            className="w-full bg-gradient-to-r from-red-500 to-red-600 hover:from-red-600 hover:to-red-700 text-white font-semibold rounded-xl px-6 py-2 shadow-md hover:shadow-lg transition-all duration-300"
                                                        >
                                                            {processing ? 'Creating...' : 'Create Lobby'}
                                                        </Button>
                                                    </DialogFooter>
                                                </form>
                                            </DialogContent>
                                        </Dialog>

                                        <div className="flex items-center justify-center space-x-6 pt-4 text-sm text-red-500">
                                            <div className="flex items-center">
                                                <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                                                </svg>
                                                Quick Setup
                                            </div>
                                            <div className="flex items-center">
                                                <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m13.5-9a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0z" />
                                                </svg>
                                                Easy Management
                                            </div>

                                        </div>
                                    </div>
                                </div>
                            )}
                        </div>


                    </div>
                </div>
            </div>

            {/* Edit Lobby Dialog */}
            <Dialog open={editDialogOpen} onOpenChange={setEditDialogOpen}>
                <DialogContent className="sm:max-w-[425px] bg-white">
                    <DialogHeader>
                        <DialogTitle className="text-2xl font-semibold text-red-700">Edit Lobby</DialogTitle>
                        <DialogDescription className="text-red-600/80">
                            Update the lobby details below.
                            {editData.code} {editData.name}
                        </DialogDescription>
                    </DialogHeader>
                    <form onSubmit={handleEditSubmit} className="space-y-4 mt-4">
                        <div className="space-y-2">
                            <Label htmlFor="edit-name" className="text-sm font-medium text-red-700">Lobby Name</Label>
                            <Input
                                id="edit-name"
                                placeholder="Enter lobby name"
                                className="border-red-200 focus:border-red-500 focus:ring-red-500"
                                value={editData.name}
                                onChange={e => setEditData('name', e.target.value)}
                            />
                            {editErrors.name && <p className="text-red-500 text-sm mt-1">{editErrors.name}</p>}
                        </div>
                        <div className="space-y-2">
                            <Label htmlFor="edit-code" className="text-sm font-medium text-red-700">Lobby Code</Label>
                            <Input
                                id="edit-code"
                                placeholder="Enter lobby code"
                                className="border-red-200 focus:border-red-500 focus:ring-red-500 font-mono"
                                value={editData.code}
                                onChange={e => setEditData('code', e.target.value)}
                            />
                            {editErrors.code && <p className="text-red-500 text-sm mt-1">{editErrors.code}</p>}
                        </div>
                        <DialogFooter className="mt-6">
                            <div className="flex space-x-3 w-full">
                                <Button
                                    type="button"
                                    variant="outline"
                                    onClick={() => {
                                        setEditDialogOpen(false);
                                        setEditingLobby(null);
                                        resetEdit();
                                    }}
                                    className="flex-1 border-gray-300 text-gray-700 hover:bg-gray-50"
                                >
                                    Cancel
                                </Button>
                                <Button
                                    type="submit"
                                    className="flex-1 bg-gradient-to-r from-red-500 to-red-600 hover:from-red-600 hover:to-red-700 text-white font-semibold rounded-xl px-6 py-2 shadow-md hover:shadow-lg transition-all duration-300"
                                >
                                    {editProcessing ? 'Updating...' : 'Update Lobby'}
                                </Button>
                            </div>
                        </DialogFooter>
                    </form>
                </DialogContent>
            </Dialog>
        </AuthenticatedLayout>


    );
};

export default OrganizerLobby;