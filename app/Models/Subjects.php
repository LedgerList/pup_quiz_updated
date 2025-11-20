<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

class Subjects extends Model
{
    //   
     protected $fillable = [
        'subject_name',
        'lobby_id',
        'quiz_title',
        'current_level',
        'start_date'
 
    ];
  
    public function lobby()
    {
        return $this->belongsTo(Lobby::class);
    }

    public function subjectsQuestions()
    {
        return $this->hasMany(SubjectQuestion::class,"subject_id")->where("deleted",0)->orderBy("id", "asc");
    }

    /**
     * Get all participants for this subject
     */
    public function participants()
    {
        return $this->hasMany(Participants::class, 'subject_id');
    }
}
