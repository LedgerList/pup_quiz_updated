<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

class Quiz extends Model
{
    use HasFactory;
    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'title',
        'user_id',
        'code',
        'status',
        'class_room_id',
        'is_class_mode'
    ];

    /**
     * Get the questions for the quiz.
     */
    public function questions(): HasMany
    {
        return $this->hasMany(Question::class);
    }

    /**
     * Get the user that owns the quiz.
     */
    public function user()
    {
        return $this->belongsTo(User::class);
    }

    /**
     * Get the class room this quiz belongs to (if in class mode)
     */
    public function classRoom()
    {
        return $this->belongsTo(ClassRoom::class, 'class_room_id');
    }
}