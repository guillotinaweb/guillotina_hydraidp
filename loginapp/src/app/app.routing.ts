import { Routes, RouterModule } from '@angular/router';

import { LoginComponent } from './login/login.component';
import { RegisterComponent } from './register/register.component';
import { RecoverComponent } from './recover/recover.component';
import { ConsentComponent } from './consent/consent.component';
import { HomeComponent } from './home/home.component';
import { LogoutComponent } from './logout/logout.component';
import { PreferencesComponent } from './preferences/preferences.component';
import { CallbackComponent } from './callback/callback.component';
import { LoggedinGuard } from './loggedin.guard';


const appRoutes: Routes = [
	{ path: '', component: HomeComponent },
    { path: 'logout', component: LogoutComponent, canActivate: [LoggedinGuard] },
    { path: 'login', component: LoginComponent },
    { path: 'profile', component: PreferencesComponent, canActivate: [LoggedinGuard] },
    { path: 'register', component: RegisterComponent },
    { path: 'recover', component: RecoverComponent },
    { path: 'consent', component: ConsentComponent },
    { path: 'callback/:provider', component: CallbackComponent },

    // otherwise redirect to home
    { path: '**', redirectTo: '' }
];

export const routing = RouterModule.forRoot(appRoutes);