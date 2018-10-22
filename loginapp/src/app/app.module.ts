import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { ReactiveFormsModule }    from '@angular/forms';

import { HttpClientModule, HTTP_INTERCEPTORS } from '@angular/common/http';
import { HttpClient } from '@angular/common/http';
import { CommonModule } from '@angular/common';
import { FlexLayoutModule } from '@angular/flex-layout';

import { AppComponent } from './app.component';
import { routing } from './app.routing';

import { environment } from '../environments/environment';
import { JWT_OPTIONS, JwtInterceptor, JwtModule } from '@auth0/angular-jwt';

import { AlertService } from './alert.service';
import { AuthenticationService } from './authentication.service';
import { UserService } from './user.service';
import { ConfigurationService } from './configuration.service';

import { LoginComponent } from './login/login.component';
import { ConsentComponent } from './consent/consent.component';
import { RegisterComponent } from './register/register.component';
import { RecoverComponent } from './recover/recover.component';
import { CallbackComponent } from './callback/callback.component';

import { LoggedinGuard } from './loggedin.guard';

import { ErrorInterceptor } from './error.interceptor';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';


import {
  MatButtonModule, MatCardModule, MatDialogModule, MatListModule, MatInputModule, MatTableModule,
  MatToolbarModule, MatMenuModule,MatIconModule, MatProgressSpinnerModule, MatCheckboxModule
} from '@angular/material';
import { LogoutComponent } from './logout/logout.component';
import { HomeComponent } from './home/home.component';
import { PreferencesComponent } from './preferences/preferences.component';
import { CookieService } from 'angular2-cookie/services/cookies.service';


export function jwtOptionsFactory (authenticationService: AuthenticationService) {
  return {
    tokenGetter: () => {
      return authenticationService.getAccessToken();
    },
    whitelistedRoutes: [`${environment.backend}`],
    blacklistedRoutes: [`${environment.backend}/@hydra-login`, `${environment.backend}/@hydra-consent`]
  };
}



@NgModule({
  declarations: [
    AppComponent,
    LoginComponent,
    ConsentComponent,
    RegisterComponent,
    RecoverComponent,
    LogoutComponent,
    HomeComponent,
    PreferencesComponent,
    CallbackComponent
  ],
  imports: [
    BrowserModule,
    ReactiveFormsModule,
    HttpClientModule,
    routing,
    BrowserAnimationsModule,
    CommonModule, 
    MatToolbarModule,
    MatButtonModule, 
    MatCardModule,
    MatInputModule,
    MatDialogModule,
    MatTableModule,
    MatMenuModule,
    MatListModule,
    MatIconModule,
    MatCheckboxModule,
    MatProgressSpinnerModule,
    FlexLayoutModule,
    JwtModule.forRoot({
      jwtOptionsProvider: {
        provide: JWT_OPTIONS,
        useFactory: jwtOptionsFactory,
        deps: [AuthenticationService]
      }
    })
  ],
  providers: [
    LoggedinGuard,
    ConfigurationService,
    AlertService,
    AuthenticationService,
    UserService,
    {
      provide: 'CONFIGURATION',
      useValue: {
        BACKEND_URL: environment.backend,
        CLIENT_TIMEOUT: 5000,
      },
    },
    { provide: HTTP_INTERCEPTORS, useClass: JwtInterceptor, multi: true },
    { provide: HTTP_INTERCEPTORS, useClass: ErrorInterceptor, multi: true },
    CookieService
  ],
  bootstrap: [AppComponent]
})
export class AppModule { }
