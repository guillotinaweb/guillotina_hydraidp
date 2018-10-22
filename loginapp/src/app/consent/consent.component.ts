import { Component, OnInit } from '@angular/core';
import { Router, ActivatedRoute } from '@angular/router';
import { FormBuilder, FormArray, FormGroup, Validators, FormControl } from '@angular/forms';
import { AuthenticationService } from '../authentication.service';
import { MatListOption } from '@angular/material/list';

@Component({
  selector: 'app-consent',
  templateUrl: './consent.component.html',
  styleUrls: ['./consent.component.css']
})
export class ConsentComponent implements OnInit {

  challenge: string;
  submitted: boolean;
  consent_data: any;

  selectedScopes: string[]
  consentForm: FormGroup;


  constructor(
      private route: ActivatedRoute,
      private authService: AuthenticationService,
      private fb: FormBuilder,) {

    this.consentForm = this.fb.group({
      remember: [false],
      request_scope: this.fb.array([])
    })
    
  }

  async ngOnInit() {
    this.submitted = false;
    this.challenge = this.route.snapshot.queryParamMap.get('consent_challenge');
    this.consent_data = await this.authService.get_consent(this.challenge);

    var self = this;
    this.consent_data.requested_scope.forEach(element => {
      (<FormArray>this.consentForm.controls.request_scope).push(this.fb.control(true));
     });

  }

  get f() { return this.consentForm.controls; }

  selectionChange(option: MatListOption) {
    this.f.request_scope.value[option.value] = option.selected;
  }

  async aprove() {
    this.submitted = true;

    // stop here if form is invalid
    if (this.consentForm.invalid) {
        return;
    }

    let scopes_array: string[] = []
    debugger;
    for (let i=0; i<this.f.request_scope.value.length; i++) {
      if (this.f.request_scope.value[i]) {
        scopes_array.push(this.consent_data.requested_scope[i])
      }
    }
    debugger;

    await this.authService.approve_consent(
      this.consent_data.challenge,
      this.consent_data.csrf,
      this.f.remember.value,
      this.consent_data.subject,
      scopes_array);
    this.submitted = false;
  }

  async deny() {
    this.submitted = true;

    // stop here if form is invalid
    if (this.consentForm.invalid) {
        return;
    }

    await this.authService.deny_consent(
      this.consent_data.challenge,
      this.consent_data.csrf);
    this.submitted = false;
  }
}
