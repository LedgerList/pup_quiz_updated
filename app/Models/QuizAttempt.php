<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class QuizAttempt extends Model
{
    use HasFactory;
    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'user_id',
        'quiz_id',
        'status',
        'score',
        'start_time',
        'end_time',
    ];

    /**
     * Get the user that owns the quiz attempt.
     */
    public function user()
    {
        return $this->belongsTo(User::class);
    }

    /**
     * Get the quiz that the attempt belongs to.
     */
    public function quiz()
    {
        return $this->belongsTo(Quiz::class);
    }
}