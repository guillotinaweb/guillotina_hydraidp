import { Component, OnInit } from '@angular/core';
import { UserService } from '../user.service';
import { FormBuilder, FormArray, FormGroup, Validators, FormControl } from '@angular/forms';

@Component({
  selector: 'app-preferences',
  templateUrl: './preferences.component.html',
  styleUrls: ['./preferences.component.css']
})
export class PreferencesComponent implements OnInit {

  profileForm: FormGroup;

  constructor(
  		public userService: UserService,
  		private fb: FormBuilder) {
    this.profileForm = this.fb.group({
      first_name: [this.userService.first_name],
      last_name: [this.userService.last_name],
    })
  }

  ngOnInit() {
  }

}
