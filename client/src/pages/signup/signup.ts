import { LoginPage } from './../login/login';
import {Component, ViewChild} from '@angular/core';
import { LoadingController, ToastController, NavController } from 'ionic-angular';
import {NgModel} from "@angular/forms";
import { AuthenticationService } from './../../services/authentication';
import {finalize} from 'rxjs/operators/finalize';

@Component({
  selector: 'page-signup',
  templateUrl: 'signup.html'
})
export class SignupPage {

  @ViewChild('username')
  usernameModel: NgModel;

  constructor(private authenticationService: AuthenticationService,
              private navCtrl: NavController,
              private loadingCtrl: LoadingController,
              private toastCtrl: ToastController) {
  }

  signup(value: any) {
    let loading = this.loadingCtrl.create({
      spinner: 'bubbles',
      content: 'Signing up ...'
    });

    loading.present();

    this.authenticationService
      .signup(value)
      .pipe(finalize(() => loading.dismiss()))
      .subscribe(
        (jwt) => this.showSuccesToast(jwt),
        err => this.handleError(err));
  }

  login() {
    this.navCtrl.push(LoginPage);
  }

  private showSuccesToast(jwt) {
    if (jwt !== 'EXISTS') {
      const toast = this.toastCtrl.create({
        message: 'Sign up successful',
        duration: 3000,
        position: 'bottom'
      });

      toast.present();
    }
    else {
      const toast = this.toastCtrl.create({
        message: 'Username already registered',
        duration: 3000,
        position: 'bottom'
      });

      toast.present();

      this.usernameModel.control.setErrors({'usernameTaken': true});
    }
  }

  handleError(error: any) {
    let message = `Unexpected error occurred`;

    const toast = this.toastCtrl.create({
      message,
      duration: 5000,
      position: 'bottom'
    });

    toast.present();
  }

}
