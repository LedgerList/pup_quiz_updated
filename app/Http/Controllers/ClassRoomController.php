<?php

namespace App\Http\Controllers;

use App\Models\ClassRoom;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use Inertia\Inertia;

class ClassRoomController extends Controller
{
    /**
     * Display a listing of classes for the authenticated teacher
     */
    public function index()
    {
        // Only teachers can view their classes
        if (Auth::user()->role !== 1) {
            abort(403, 'Only teachers can access this page.');
        }

        $classes = ClassRoom::where('teacher_id', Auth::id())
            ->withCount('students')
            ->orderBy('created_at', 'desc')
            ->get();

        return Inertia::render('ClassManagement', [
            'classes' => $classes
        ]);
    }

    /**
     * Display classes for students (classes they're enrolled in)
     */
    public function myClasses()
    {
        // Only students can view their enrolled classes
        if (Auth::user()->role !== 2) {
            abort(403, 'Only students can access this page.');
        }

        $classes = Auth::user()
            ->classRooms()
            ->with('teacher')
            ->withCount('students')
            ->orderBy('pivot_joined_at', 'desc')
            ->get();

        return Inertia::render('MyClasses', [
            'classes' => $classes
        ]);
    }

    /**
     * Store a newly created class
     */
    public function store(Request $request)
    {
        // Only teachers can create classes
        if (Auth::user()->role !== 1) {
            abort(403, 'Only teachers can create classes.');
        }

        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'subject' => 'nullable|string|max:255',
            'section' => 'nullable|string|max:255',
            'description' => 'nullable|string',
        ]);

        if ($validator->fails()) {
            return back()->withErrors($validator->errors());
        }

        $classRoom = ClassRoom::create([
            'name' => $request->name,
            'class_code' => ClassRoom::generateClassCode(),
            'teacher_id' => Auth::id(),
            'subject' => $request->subject,
            'section' => $request->section,
            'description' => $request->description,
            'is_active' => true,
        ]);

        return back()->with('success', 'Class created successfully! Class Code: ' . $classRoom->class_code);
    }

    /**
     * Join a class using class code (for students)
     */
    public function join(Request $request)
    {
        // Only students can join classes
        if (Auth::user()->role !== 2) {
            abort(403, 'Only students can join classes.');
        }

        $validator = Validator::make($request->all(), [
            'class_code' => 'required|string|exists:class_rooms,class_code',
        ], [
            'class_code.exists' => 'Invalid class code. Please check and try again.',
        ]);

        if ($validator->fails()) {
            return back()->withErrors($validator->errors());
        }

        $classRoom = ClassRoom::where('class_code', $request->class_code)
            ->where('is_active', true)
            ->first();

        if (!$classRoom) {
            return back()->withErrors(['class_code' => 'Class not found or is inactive.']);
        }

        // Check if student is already enrolled
        if ($classRoom->students()->where('student_id', Auth::id())->exists()) {
            return back()->withErrors(['class_code' => 'You are already enrolled in this class.']);
        }

        // Enroll student
        $classRoom->students()->attach(Auth::id(), [
            'joined_at' => now()
        ]);

        return back()->with('success', 'Successfully joined class: ' . $classRoom->name);
    }

    /**
     * Display the specified class with roster
     */
    public function show(ClassRoom $classRoom)
    {
        // Only the teacher who owns the class can view details
        if ($classRoom->teacher_id !== Auth::id()) {
            abort(403, 'You are not authorized to view this class.');
        }

        $classRoom->load(['students', 'quizzes']);

        return Inertia::render('ClassDetails', [
            'classRoom' => $classRoom
        ]);
    }

    /**
     * Update the specified class
     */
    public function update(Request $request, ClassRoom $classRoom)
    {
        // Only the teacher who owns the class can update it
        if ($classRoom->teacher_id !== Auth::id()) {
            abort(403, 'You are not authorized to update this class.');
        }

        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'subject' => 'nullable|string|max:255',
            'section' => 'nullable|string|max:255',
            'description' => 'nullable|string',
            'is_active' => 'boolean',
        ]);

        if ($validator->fails()) {
            return back()->withErrors($validator->errors());
        }

        $classRoom->update($request->only(['name', 'subject', 'section', 'description', 'is_active']));

        return back()->with('success', 'Class updated successfully!');
    }

    /**
     * Remove a student from the class
     */
    public function removeStudent(Request $request, ClassRoom $classRoom, User $student)
    {
        // Only the teacher who owns the class can remove students
        if ($classRoom->teacher_id !== Auth::id()) {
            abort(403, 'You are not authorized to remove students from this class.');
        }

        $classRoom->students()->detach($student->id);

        return back()->with('success', 'Student removed from class successfully!');
    }

    /**
     * Delete the specified class
     */
    public function destroy(ClassRoom $classRoom)
    {
        // Only the teacher who owns the class can delete it
        if ($classRoom->teacher_id !== Auth::id()) {
            abort(403, 'You are not authorized to delete this class.');
        }

        $classRoom->delete();

        return redirect()->route('classes.index')->with('success', 'Class deleted successfully!');
    }
}
