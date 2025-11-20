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
        Schema::create('class_student', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('class_room_id');
            $table->unsignedBigInteger('student_id');
            $table->timestamp('joined_at')->useCurrent();
            $table->timestamps();

            $table->foreign('class_room_id')->references('id')->on('class_rooms')->onDelete('cascade');
            $table->foreign('student_id')->references('id')->on('users')->onDelete('cascade');
            
            // Prevent duplicate enrollments
            $table->unique(['class_room_id', 'student_id'], 'unique_class_student');
            $table->index('class_room_id');
            $table->index('student_id');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('class_student');
    }
};
