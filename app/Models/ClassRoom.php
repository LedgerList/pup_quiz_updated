<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Database\Eloquent\Relations\HasMany;

class ClassRoom extends Model
{
    protected $fillable = [
        'name',
        'class_code',
        'teacher_id',
        'subject',
        'section',
        'description',
        'is_active',
    ];

    protected $casts = [
        'is_active' => 'boolean',
    ];

    /**
     * Get the teacher who owns this class
     */
    public function teacher(): BelongsTo
    {
        return $this->belongsTo(User::class, 'teacher_id');
    }

    /**
     * Get all students enrolled in this class
     */
    public function students(): BelongsToMany
    {
        return $this->belongsToMany(User::class, 'class_student', 'class_room_id', 'student_id')
            ->withPivot('joined_at')
            ->withTimestamps();
    }

    /**
     * Get all quizzes assigned to this class
     */
    public function quizzes(): HasMany
    {
        return $this->hasMany(Quiz::class, 'class_room_id');
    }

    /**
     * Generate a unique class code
     */
    public static function generateClassCode(): string
    {
        do {
            $code = strtoupper(substr(md5(uniqid(rand(), true)), 0, 8));
        } while (self::where('class_code', $code)->exists());

        return $code;
    }
}
