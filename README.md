# Documentation Authentication

## Overview

This module handles user authentication using NestJS. It provides routes for user signup, signin, logout, and token refreshing.

## AuthController


## localhost:3000/

### 1. Signup Local User

- **Route:** `/auth/local/signup`
- **Method:** `POST`
- **Description:** Create a new local user.
- **HTTP Code:** 201 (Created)

## Signin Local User

- **Route:** `/auth/local/signin`
- **Method:** `POST`
- **Description:** Authenticate a local user.
- **HTTP Code:** 201 (Created)

## Logout User

- **Route:** `/auth/logout`
- **Method:** `POST`
- **Description:** Logout a user.
- **HTTP Code:** 201 (OK)

## Refresh Access Token
- **Route**: /auth/refresh
- **Method**: POST
- **Description**: Refresh the access token using a refresh token.
- **HTTP Code**: 200 (OK)

  ## Decorators and Guards

**@Public()**: Marks a route as public, requiring no authentication.

**@GetCurrentUserId()**: Decorator to get the current user's ID.

**@GetCurrentUser('refreshToken')**: Decorator to get the current user's refresh token.

**@UseGuards(RtGuard)**: Guard to validate the refresh token.
