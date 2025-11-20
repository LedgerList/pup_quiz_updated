<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->string('username')->nullable()->unique()->after('email');
            $table->string('student_number')->nullable()->after('username');
            $table->string('program')->nullable()->after('student_number');
            $table->string('section')->nullable()->after('program');
            $table->integer('role')->nullable()->after('section'); // 1 = teacher, 2 = student, 3 = organizer, 4 = member
            $table->string('department')->nullable()->after('role');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->dropColumn(['username', 'student_number', 'program', 'section', 'role', 'department']);
        });
    }
};
