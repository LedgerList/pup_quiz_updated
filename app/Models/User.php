<?php

namespace App\Models;

use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Illuminate\Auth\Notifications\ResetPassword;
use Laravel\Sanctum\HasApiTokens; 

class User extends Authenticatable
{
    use HasApiTokens, Notifiable;
    protected $table = 'users';

    protected $fillable = [
        'name',
        'email',
        'password',
        'student_number',
        'program',
        'section',
        'username',
        'role', // 1 = teacher, 2 = student, 3 = organizer, 4 = member
        'department'
    ];

    protected $hidden = [
        'password',
        'remember_token',
        'student_number', // Hide student number from API responses
        'email', // Hide email from API responses (can be made visible when needed)
    ];

    public function quizzes() 
    {
        return $this->hasMany(Quiz::class); 
    }

    public function quizAttempts() 
    {
        return $this->hasMany(QuizAttempt::class); 
    }

    /**
     * Get all classes this user (student) is enrolled in
     */
    public function classRooms()
    {
        return $this->belongsToMany(ClassRoom::class, 'class_student', 'student_id', 'class_room_id')
            ->withPivot('joined_at')
            ->withTimestamps();
    }

    /**
     * Get all classes this user (teacher) has created
     */
    public function createdClasses()
    {
        return $this->hasMany(ClassRoom::class, 'teacher_id');
    }
    protected $casts = [
        'email_verified_at' => 'datetime',
    ];

    /**
     * Send the password reset notification.
     *
     * @param  string  $token
     * @return void
     */
    public function sendPasswordResetNotification($token): void
    {
        // Use Laravel's built-in ResetPassword notification
        // It automatically generates the reset URL and sends the email
        $this->notify(new ResetPassword($token));
    }
}
