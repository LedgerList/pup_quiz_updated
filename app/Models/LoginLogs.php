<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class LoginLogs extends Model
{
    //
    protected $table = "login_logs";
    protected $fillable = [
        'user_id',
        'email'
    ];
}
