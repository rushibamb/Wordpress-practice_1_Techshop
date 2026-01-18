<?php

namespace GetAstra\Transformers;

use GetAstra\Models\User;
use League\Fractal\TransformerAbstract;

class UserTransformer extends TransformerAbstract
{

    public function transform(User $user)
    {
        return [
            'id'        => (int)$user->id,
            'email'     => $user->email,
            'createdAt' => $user->created_at ? $user->created_at->toIso8601String() : null,
            'updatedAt' => $user->update_at ? $user->update_at->toIso8601String() : null,
            'username'  => $user->username,
            'bio'       => $user->bio,
            'image'     => $user->image,
            'token'     => $user->token,
        ];
    }
}