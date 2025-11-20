<?php

namespace App\Providers;

use Illuminate\Support\Facades\Vite;
use Illuminate\Support\Facades\Auth; // Add this import
use Illuminate\Support\ServiceProvider;
use Inertia\Inertia; // Add this import

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        // Share user and role with Inertia globally
        Inertia::share([
            'auth' => fn () => [
                'user' => Auth::user() ? [
                    'id' => Auth::user()->id,
                    'name' => Auth::user()->name,
                    'email' => Auth::user()->email,
                    'role' => Auth::user()->role, // Get role directly from user model
                ] : null,
                'role' => Auth::user()?->role ?? session('role'), // Fallback to session if user not loaded
            ],
        ]);

        Vite::prefetch(concurrency: 3);
    }
}
