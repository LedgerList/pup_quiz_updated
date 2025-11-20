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
        Schema::create('class_rooms', function (Blueprint $table) {
            $table->id();
            $table->string('name');
            $table->string('class_code')->unique(); // Unique code for students to join
            $table->unsignedBigInteger('teacher_id'); // Teacher who created the class
            $table->string('subject')->nullable(); // Optional subject name
            $table->string('section')->nullable(); // Optional section
            $table->text('description')->nullable(); // Optional description
            $table->boolean('is_active')->default(true); // Whether class is active
            $table->timestamps();

            $table->foreign('teacher_id')->references('id')->on('users')->onDelete('cascade');
            $table->index('class_code');
            $table->index('teacher_id');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('class_rooms');
    }
};
